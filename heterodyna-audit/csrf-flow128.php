<?php
if (!defined('ABSPATH')) { exit; }
/**
 * Etap V 3/5 — read-only WordPress entrypoint / write / nonce / capability correlation.
 * This does NOT execute handlers, and observing a guard does not prove that it enforces a denial.
 * No raw source or request values are exported.
 */
function hsa128_tokens($code) {
    $out=array();$line=1;
    foreach(token_get_all($code) as $t){
        $v=is_array($t)?$t[1]:$t;$at=is_array($t)?$t[2]:$line;
        $out[]=array('id'=>is_array($t)?$t[0]:0,'text'=>$v,'line'=>(int)$at);
        $line=$at+substr_count($v,"\n");
    }
    return $out;
}
function hsa128_next($tokens,$i){
    $n=count($tokens);
    while($i<$n && in_array($tokens[$i]['id'],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$i++;
    return $i;
}
/** Extract token-separated arguments without executing or evaluating them. */
function hsa128_arguments($tokens,$at) {
    $n=count($tokens);$p=hsa128_next($tokens,$at+1);
    if($p >= $n || $tokens[$p]['text']!=='(')return null;
    $depth=0;$nested=0;$args=array();$part='';
    for($k=$p;$k<$n;$k++){
        $t=$tokens[$k];$v=$t['text'];
        if($t['id']===T_COMMENT || $t['id']===T_DOC_COMMENT)continue;
        if($v==='('){$depth++;if($depth===1)continue;}
        elseif($v===')'){$depth--;if($depth===0){$args[]=trim($part);return $args;}}
        elseif($v==='[' || $v==='{')$nested++;
        elseif($v===']' || $v==='}')$nested=max(0,$nested-1);
        if($v===',' && $depth===1 && $nested===0){$args[]=trim($part);$part='';continue;}
        $part.=$v;
    }
    return null;
}
function hsa128_unquote($value) {
    $value=trim($value);
    if(strlen($value)>=2 && ($value[0]==='\''||$value[0]==='"') && substr($value,-1)===$value[0])return stripcslashes(substr($value,1,-1));
    return null;
}
function hsa128_callback($raw) {
    $raw=trim((string)$raw);
    $plain=hsa128_unquote($raw);
    if($plain!==null)return $plain;
    if(preg_match('/^(?:array\s*\(|\[)/i',$raw)){
        preg_match_all('/([\'\"])([A-Za-z_]\w*)\1/',$raw,$m);
        if(!empty($m[2])){
            $method=end($m[2]);$class=null;
            if(preg_match('/^\s*(?:array\s*\(|\[)\s*([\'\"])([A-Za-z_]\w*)\1\s*,/',$raw,$c))$class=$c[2];
            if(preg_match('/^\s*(?:array\s*\(|\[)\s*([A-Za-z_]\w*)::class\s*,/i',$raw,$c))$class=$c[1];
            return $class?$class.'::'.$method:$method;
        }
    }
    return null; // closures, functions built dynamically and external callbacks are not guessed
}
/** Named functions and methods, bounded to their own lexical body (no cross-file claims). */
function hsa128_functions($t) {
    $n=count($t);$level=0;$classes=array();$pending=null;$list=array();
    for($i=0;$i<$n;$i++){
        $id=$t[$i]['id'];$v=$t[$i]['text'];
        if(in_array($id,array(T_CLASS,T_TRAIT,T_INTERFACE),true)){
            $j=hsa128_next($t,$i+1);
            // Skip anonymous class expressions.
            if($j<$n && $t[$j]['id']===T_STRING)$pending=$t[$j]['text'];
        }
        if($v==='{'){
            $level++;
            if($pending!==null){$classes[]=array('depth'=>$level,'name'=>$pending);$pending=null;}
        } elseif($v==='}') {
            if($classes && end($classes)['depth']===$level)array_pop($classes);
            $level=max(0,$level-1);
        }
        if($id!==T_FUNCTION)continue;
        $j=hsa128_next($t,$i+1);
        if($j<$n && $t[$j]['text']==='&')$j=hsa128_next($t,$j+1);
        if($j >= $n || $t[$j]['id']!==T_STRING)continue; // anonymous callbacks are not attributed to a guessed function
        $name=$t[$j]['text'];$open=null;
        $parens=0;
        for($k=$j+1;$k<$n;$k++){
            if($t[$k]['text']==='(')$parens++;
            elseif($t[$k]['text']===')')$parens--;
            if($parens===0 && $t[$k]['text']==='{'){$open=$k;break;}
            if($parens===0 && $t[$k]['text']===';')break;
        }
        if($open===null)continue;
        $depth=1;$close=null;
        for($k=$open+1;$k<$n;$k++){
            if($t[$k]['text']==='{')$depth++;
            elseif($t[$k]['text']==='}' && --$depth===0){$close=$k;break;}
        }
        if($close===null)continue;
        $class=$classes?end($classes)['name']:null;
        $list[]=array('name'=>$name,'class'=>$class,'line'=>$t[$i]['line'],
            'body'=>array_slice($t,$open+1,$close-$open-1));
    }
    return $list;
}
function hsa128_calls($body) {
    $writes=array();$nonce=array();$capability=array();$other=array();
    $writesList=array('update_option','add_option','delete_option','update_site_option','delete_site_option',
        'update_post_meta','add_post_meta','delete_post_meta','update_user_meta','delete_user_meta',
        'update_term_meta','delete_term_meta','wp_insert_post','wp_update_post','wp_delete_post','wp_trash_post',
        'wp_insert_user','wp_update_user','wp_create_user','wp_delete_user','wp_set_password',
        'wp_set_object_terms','wp_set_post_terms','wp_handle_upload','media_handle_upload','media_handle_sideload',
        'wp_upload_bits','move_uploaded_file','file_put_contents','unlink','rename','mkdir','rmdir','fwrite',
        'add_user_meta','delete_metadata','update_metadata');
    $nonces=array('check_ajax_referer','check_admin_referer','wp_verify_nonce','wp_verify_nonce_and_login');
    $caps=array('current_user_can','user_can','current_user_can_for_site','is_user_logged_in');
    $n=count($body);
    for($i=0;$i<$n;$i++){
        if($body[$i]['id']!==T_STRING)continue;
        $name=strtolower($body[$i]['text']);$j=hsa128_next($body,$i+1);
        if($j>=$n || $body[$j]['text']!=='(')continue;
        $prev=$i>0?$body[hsa128_prev($body,$i-1)]['text']:'';
        if(in_array($prev,array('function','new'),true))continue;
        $item=array('call'=>$name,'line'=>$body[$i]['line'],'index'=>$i);
        if(in_array($name,$writesList,true))$writes[]=$item;
        if(in_array($name,$nonces,true))$nonce[]=$item;
        if(in_array($name,$caps,true))$capability[]=$item;
    }
    return array('writes'=>$writes,'nonce'=>$nonce,'capability'=>$capability);
}
function hsa128_prev($t,$i) {
    while($i>0 && in_array($t[$i]['id'],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$i--;
    return $i;
}
function hsa128_hooks($t) {
    $out=array();$n=count($t);
    for($i=0;$i<$n;$i++){
        if($t[$i]['id']!==T_STRING)continue;
        $fn=strtolower($t[$i]['text']);
        if(!in_array($fn,array('add_action','register_rest_route'),true))continue;
        $args=hsa128_arguments($t,$i);
        if(!$args)continue;
        if($fn==='add_action'){
            $hook=hsa128_unquote($args[0]??'');
            if($hook===null || !preg_match('/^(wp_ajax(?:_nopriv)?_|admin_post(?:_nopriv)?_)/',$hook))continue;
            $out[]=array('entry'=>$hook,'type'=>'hook','callback'=>hsa128_callback($args[1]??''),
                'line'=>$t[$i]['line'],'method'=>'POST_or_unknown','permission'=>'not_applicable',
                'public'=>strpos($hook,'_nopriv_')!==false);
        } else {
            $namespace=hsa128_unquote($args[0]??'');$route=hsa128_unquote($args[1]??'');
            if($namespace===null || $route===null)continue;
            $options=$args[2]??'';
            $method='unknown';$callback=null;$permission='not_observed';
            if(preg_match('/[\'\"]methods[\'\"]\s*=>\s*([^,\]\)]+)/i',$options,$m)){
                $method=hsa128_unquote(trim($m[1]))??trim($m[1]);
                if(preg_match('/\bEDITABLE\b/i',$method))$method='POST,PUT,PATCH';
                if(preg_match('/\bDELETABLE\b/i',$method))$method='DELETE';
            }
            if(preg_match('/[\'\"]callback[\'\"]\s*=>\s*(array\s*\([^)]*\)|\[[^]]*\]|[\'\"][^\'\"]+[\'\"])/i',$options,$m))$callback=hsa128_callback($m[1]);
            if(preg_match('/[\'\"]permission_callback[\'\"]\s*=>\s*([^,\]\)]+)/i',$options,$m)){
                $p=trim($m[1]);$permission=(stripos($p,'__return_true')!==false)?'explicit_public':'declared_not_verified';
            }
            $out[]=array('entry'=>'/'.$namespace.'/'.ltrim($route,'/'),'type'=>'REST','callback'=>$callback,
                'line'=>$t[$i]['line'],'method'=>$method,'permission'=>$permission,'public'=>$permission==='explicit_public');
        }
    }
    return $out;
}
function hsa128_match_handler($functions,$name) {
    if(!$name)return null;
    $matches=array();$parts=explode('::',$name);$short=end($parts);$expected=count($parts)>1?$parts[0]:null;
    foreach($functions as $f){
        if(strcasecmp($f['name'],$short)!==0)continue;
        if($expected!==null && strcasecmp((string)$f['class'],$expected)!==0)continue;
        $matches[]=$f;
    }
    // Do not attribute two unrelated classes' methods to a single handler.
    return count($matches)===1?$matches[0]:null;
}
function hsa128_audit($code,$file,$limit=15) {
    $tokens=hsa128_tokens($code);$functions=hsa128_functions($tokens);$hooks=hsa128_hooks($tokens);
    $items=array();$resolved=0;$unresolved=0;$writes=0;$nonceMissing=0;
    foreach($hooks as $h){
        $func=hsa128_match_handler($functions,$h['callback']);
        if(!$func){$unresolved++;continue;}
        $resolved++;$calls=hsa128_calls($func['body']);
        if(!$calls['writes'])continue;
        foreach($calls['writes'] as $write){
            $writes++;
            $beforeNonce=array_values(array_filter($calls['nonce'],static function($c)use($write){return $c['index']<$write['index'];}));
            $beforeCap=array_values(array_filter($calls['capability'],static function($c)use($write){return $c['index']<$write['index'];}));
            $nonceStatus='not_checked';
            if($h['type']==='REST')$nonceStatus='rest_nonce_not_universal_requirement';
            elseif(!$beforeNonce){$nonceStatus='no_verification_before_write_observed';$nonceMissing++;}
            elseif(count(array_filter($beforeNonce,static function($x){return in_array($x['call'],array('check_ajax_referer','check_admin_referer'),true);})))$nonceStatus='nonce_check_call_observed_not_proven';
            else $nonceStatus='verification_call_observed_branch_not_proven';
            $capStatus=$beforeCap?'capability_call_observed_not_proven':'no_capability_call_before_write_observed';
            $flag=$h['type']==='REST' ?
                ($h['permission']==='not_observed'?'rest_permission_declaration_not_observed':($h['permission']==='explicit_public'?'rest_declared_public_write':'rest_permission_not_verified')):
                ($nonceStatus==='no_verification_before_write_observed'?'possible_missing_csrf_control':'write_guard_implementation_review');
            if(count($items)>=$limit)continue;
            $item=array('file'=>$file,'entry'=>$h['entry'],'type'=>$h['type'],'method'=>$h['method'],
                'entry_line'=>$h['line'],'handler'=>($func['class']?$func['class'].'::':'').$func['name'],
                'handler_line'=>$func['line'],'sink'=>$write['call'],'sink_line'=>$write['line'],
                'nonce'=>$nonceStatus,'capability'=>$capStatus,'permission'=>$h['permission'],
                'public'=>$h['public'],'control'=>$flag,'verdict'=>'static_review_candidate',
                'reason'=>'Statyczne powiązanie deklaracji wejścia z zapisem w tym samym pliku. Nie dowodzi osiągalności gałęzi, wykonania operacji ani skuteczności kontroli.',
                'recommendation'=>($h['type']==='REST'?'Sprawdź permission_callback i właściwą kontrolę uprawnień do obiektu.':'Sprawdź weryfikację nonce, uprawnienia i faktyczne odrzucanie żądań przed operacją zapisu.'),
                'evidence_sha256'=>'');
            $item['evidence_sha256']=hash('sha256',json_encode(array($file,$item['entry'],$item['entry_line'],$item['handler'],$item['sink'],$item['sink_line'],$item['nonce'],$item['permission'],$item['capability'])));
            $items[]=$item;
        }
    }
    return array('registrations'=>count($hooks),'handlers_resolved'=>$resolved,'handlers_unresolved'=>$unresolved,
        'write_operations_seen'=>$writes,'missing_nonce_candidates'=>$nonceMissing,'items'=>$items,'items_found'=>$writes);
}
function hsa128_summary($state) {
    $x=$state['csrf128']??array();
    return array('files_scanned'=>(int)($x['files_scanned']??0),'registrations'=>(int)($x['registrations']??0),
        'handlers_resolved'=>(int)($x['handlers_resolved']??0),'handlers_unresolved'=>(int)($x['handlers_unresolved']??0),
        'write_operations_seen'=>(int)($x['write_operations_seen']??0),
        'missing_nonce_candidates'=>(int)($x['missing_nonce_candidates']??0),
        'candidates_found'=>(int)($x['candidates_found']??0),'candidates_stored'=>count($x['items']??array()),
        'storage_limit'=>(int)($x['storage_limit']??180),'confirmed_vulnerabilities'=>0,
        'items'=>$x['items']??array(),
        'scope'=>'wp-content plugins/themes/mu-plugins; registered AJAX/admin-post/REST callbacks with same-file named PHP handlers; read-only',
        'limitations'=>array('Nie rozpoznaje wszystkich dynamicznych wywołań, closures, dziedziczenia, metod między plikami ani złożonych struktur REST.',
          'Obecność wywołania nonce/capability nie oznacza wymuszenia kontroli; brak wywołania nie dowodzi exploita.',
          'Dla REST brak nonce nie stanowi sam w sobie luki: zasadnicza jest autoryzacja i uprawnienia.',
          'Nie wysyła żądań zmieniających stan ani nie testuje CSRF w przeglądarce.',
          'Zapisano ograniczoną liczbę śladów, ale licznik obejmuje wykryte operacje w dopasowanych handlerach.'));
}
