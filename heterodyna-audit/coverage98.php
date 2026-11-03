<?php
if (!defined('ABSPATH')) { exit; }
/**
 * Stage II 8/8: evidence-grounded coverage inventory. No external calls, no
 * handler invocation. Never converts a transport observation into a security verdict.
 * All totals refer to registrations visible to the current WP admin request.
 */
function hsa98_component($file) {
    $file=(string)$file;
    if (preg_match('~^wp-content/plugins/([^/]+)/~', $file,$m)) return 'plugin:'.$m[1];
    if (preg_match('~^wp-content/plugins/([^/]+\.php)$~',$file,$m))return 'plugin:'.$m[1];
    if (preg_match('~^wp-content/themes/([^/]+)/~',$file,$m))return 'theme:'.$m[1];
    if (preg_match('~^wp-content/mu-plugins/([^/]+)~',$file,$m))return 'must_use:'.$m[1];
    if (preg_match('~^wp-(?:admin|includes)/~',$file))return 'core';
    return 'unmapped';
}
function hsa98_record_hash($r) {
    return hash('sha256', implode('|', array((string)($r['id']??''),(string)($r['target']??''),
        (string)($r['verdict']??''),(string)($r['http']['status']??0),
        (string)($r['http']['response_sha256']??''),(string)($r['proof']??''))));
}
function hsa98_backlog(&$items,&$totals,$record,$limit=10000) {
    $key=(string)$record['reason'];
    $totals[$key]=($totals[$key]??0)+1;
    if(count($items)<$limit)$items[]=$record;
}
function hsa98_coverage($s) {
    $entry=(array)($s['entry_map']??array());$results=(array)($s['engine_results']??array());
    $indexes=array();$evidence=array('records'=>0,'valid'=>0,'invalid'=>0,'missing'=>0,'duplicates'=>0,'http_observations'=>0,'http_with_valid_evidence'=>0);
    $seenIds=array();$observed=array();$invalidIds=array();
    foreach($results as $r) {
        if(!is_array($r))continue;
        $evidence['records']++;
        $id=(string)($r['id']??'');
        if($id!=='' && isset($seenIds[$id]))$evidence['duplicates']++;
        else if($id!=='')$seenIds[$id]=true;
        $sha=(string)($r['evidence_sha256']??'');
        if($sha===''){$evidence['missing']++;$invalidIds[]=$id;}
        elseif(!preg_match('/^[a-f0-9]{64}$/D',$sha)||!hash_equals(hsa98_record_hash($r),$sha)){$evidence['invalid']++;$invalidIds[]=$id;}
        else $evidence['valid']++;
        // Only explicit real external HTTP to an observed GET route is attributed.
        if(!in_array((string)($r['kind']??''),array('rest_get','component_param_get','route86_dynamic_get'),true)||empty($r['executed']))continue;
        $evidence['http_observations']++;
        if($sha===''||!hash_equals(hsa98_record_hash($r),$sha))continue;
        $evidence['http_with_valid_evidence']++;
        $path=(string)(($r['kind']??'')==='rest_get'?($r['target']??''):($r['route_pattern']??''));
        if($path!=='' && !isset($observed[$path]))$observed[$path]=array('id'=>$id,'http'=>(int)($r['http']['status']??0),'sha256'=>$sha,'kind'=>$r['kind']);
    }
    $observedHooks=array();
    foreach($results as $r){
        if(($r['kind']??'')!=='real108_hook' || empty($r['executed']) ||
           empty($r['receiver_registered_match']) || empty($r['hook_dispatch']))continue;
        $sha=(string)($r['evidence_sha256']??'');
        if($sha==='' || !hash_equals(hsa98_record_hash($r),$sha))continue;
        $key=(string)($r['target']??'').'|'.(string)($r['callback_file']??'').'|'.(int)($r['callback_line']??0);
        $observedHooks[$key]=array('id'=>$r['id']??'','completed'=>!empty($r['hook_completed']),'sha256'=>$sha);
    }
    $verifiedReal=array();
    foreach($results as $r){
        if(!in_array(($r['kind']??''),array('real10_get','real102_param','real104_context','real106_repeat'),true)||empty($r['callback_verified'])||empty($r['executed']))continue;
        $sha=(string)($r['evidence_sha256']??'');
        if($sha===''||!hash_equals(hsa98_record_hash($r),$sha))continue;
        $key=(string)($r['target']??'').'|'.(string)($r['callback_file']??'').'|'.(int)($r['callback_line']??0);
        $verifiedReal[$key]=array('id'=>(string)($r['id']??''),'sha256'=>$sha,'http'=>(int)($r['http']['status']??0));
    }
    $catalog=(array)($s['catalog']??array());
    foreach(array('plugins'=>'plugin','themes'=>'theme') as $group=>$type){
        foreach((array)($catalog[$group]??array()) as $c){
            if(!is_array($c)||!isset($c['slug']))continue;
            $key=$type.':'.$c['slug'];
            $indexes[$key]=array('key'=>$key,'name'=>(string)($c['name']??$key),'active'=>!empty($c['active']),
              'rest_registrations'=>0,'get_registrations'=>0,'get_route_observed'=>0,
              'state_changing_not_tested'=>0,'hooks_not_tested'=>0,'shortcodes_not_tested'=>0,
              'blocks_not_tested'=>0,'widgets_not_tested'=>0,'notes'=>'Zarejestrowana trasa z odpowiedzią HTTP nie dowodzi wykonania konkretnego callbacku.');
        }
    }
    $summary=array('registered_rest_paths'=>0,'registered_rest_handlers'=>0,'registered_rest_method_entries'=>0,
        'real_get_handlers_executed'=>0,
        'registered_get_handlers'=>0,'get_handlers_with_route_http'=>0,'get_handlers_without_route_http'=>0,
        'write_handlers_without_proof'=>0,'other_handlers_without_proof'=>0,'mapped_rest_handlers'=>0,
        'unmapped_rest_handlers'=>0,'registration_limits'=>array_sum(array_map('intval',(array)($entry['limits']??array()))),
        'registered_hooks'=>0,'hooks_observed_http'=>0,'hooks_chain_complete'=>0,'registered_shortcodes'=>0,'registered_blocks'=>0,'registered_widgets'=>0,
        'forms_discovered'=>(int)($s['frontend8']['forms_found']??0),'forms_submitted'=>0,
        'files_read'=>(int)($s['checked']??0),'files_indexed'=>count((array)($s['files']??array())),
        'files_skipped'=>(int)($s['skipped']??0));
    $backlog=array();$reasonCounts=array();$handlers=array();$methodsModify=array('POST','PUT','PATCH','DELETE');
    $routes=(array)($entry['rest']??array());$summary['registered_rest_paths']=count($routes);
    foreach($routes as $route=>$entries){
        foreach((array)$entries as $h){
            if(!is_array($h))continue;
            $summary['registered_rest_handlers']++;
            $source=(array)($h['callback']??array());$file=(string)($source['file']??'');
            $component=hsa98_component($file);$line=(int)($source['line']??0);
            if($file!=='')$summary['mapped_rest_handlers']++;else $summary['unmapped_rest_handlers']++;
            $methodList=(array)($h['methods']??array());
            if(!$methodList)$methodList=array('UNKNOWN');
            foreach(array_unique($methodList) as $method){
                $method=strtoupper((string)$method);$summary['registered_rest_method_entries']++;
                $isGet=$method==='GET';$isWrite=in_array($method,$methodsModify,true);
                $realKey=(string)$route.'|'.$file.'|'.$line;
                $isVerified=$isGet&&isset($verifiedReal[$realKey]);
                if($isVerified)$summary['real_get_handlers_executed']++;
                $isObserved=$isGet && isset($observed[(string)$route]);
                if($isGet){$summary['registered_get_handlers']++;$summary[$isObserved?'get_handlers_with_route_http':'get_handlers_without_route_http']++;}
                elseif($isWrite)$summary['write_handlers_without_proof']++;
                else $summary['other_handlers_without_proof']++;
                if(isset($indexes[$component])){
                    $indexes[$component]['rest_registrations']++;
                    if($isGet){$indexes[$component]['get_registrations']++;if($isObserved)$indexes[$component]['get_route_observed']++;}
                    if($isWrite)$indexes[$component]['state_changing_not_tested']++;
                }
                $reason=$isGet?($isVerified?'real_callback_executed_no_vulnerability_conclusion':($isObserved?'route_http_observed_callback_not_verified':'get_route_no_http_evidence')):

                    ($isWrite?'write_handler_not_tested':'non_get_handler_not_tested');
                $row=array('kind'=>'REST','name'=>substr((string)$route,0,250),'method'=>$method,'component'=>$component,
                    'file'=>$file,'line'=>$line,'permission'=>(string)($h['permission_declaration']??'unknown'),
                    'status'=>$reason,'evidence_id'=>$isVerified?(string)$verifiedReal[$realKey]['id']:($isObserved?(string)$observed[$route]['id']:''),
                    'http'=>$isObserved?(int)$observed[$route]['http']:null,
                    'evidence_sha256'=>$isVerified?(string)$verifiedReal[$realKey]['sha256']:($isObserved?(string)$observed[$route]['sha256']:''));
                // Include all REST rows for complete details, including duplicated route handlers.
                if(count($handlers)<3500)$handlers[]=$row;
                if(!$isObserved&&!$isVerified){
                    $priority=$isWrite?1:($isGet?3:2);
                    if(($row['permission']==='missing_callback')&&$isWrite)$priority=1;
                    hsa98_backlog($backlog,$reasonCounts,array('priority'=>$priority,'kind'=>'REST','name'=>$row['name'],
                        'method'=>$method,'component'=>$component,'file'=>$file,'line'=>$line,'reason'=>$reason,'permission'=>$row['permission']));
                }
            }
        }
    }
    foreach((array)($entry['entries']??array()) as $v){
        if(!is_array($v))continue;
        $kind=(string)($v['kind']??'');
        $field=array('hook'=>'registered_hooks','shortcode'=>'registered_shortcodes','block'=>'registered_blocks','widget'=>'registered_widgets');
        if(!isset($field[$kind]))continue;
        $summary[$field[$kind]]++;
        $file=(string)($v['source']['file']??'');$component=hsa98_component($file);
        $indexField=array('hook'=>'hooks_not_tested','shortcode'=>'shortcodes_not_tested','block'=>'blocks_not_tested','widget'=>'widgets_not_tested');
        $hookKey=(string)($v['name']??'').'|'.$file.'|'.(int)($v['source']['line']??0);
        $hookObserved=$kind==='hook' && isset($observedHooks[$hookKey]);
        if($hookObserved){
            $summary['hooks_observed_http']++;
            if(!empty($observedHooks[$hookKey]['completed']))$summary['hooks_chain_complete']++;
        }
        if(isset($indexes[$component]) && !$hookObserved)$indexes[$component][$indexField[$kind]]++;
        $priority=$kind==='hook' && !empty($v['public'])?1:($kind==='hook'?2:4);
        $reason=$hookObserved?'hook_http_dispatch_observed_no_security_verdict':$kind.'_handler_not_tested';
        hsa98_backlog($backlog,$reasonCounts,array('priority'=>$priority,'kind'=>$kind,'name'=>(string)($v['name']??''),
            'method'=>$kind==='hook'?'POST':'runtime','component'=>$component,'file'=>$file,
            'line'=>(int)($v['source']['line']??0),'reason'=>$reason,
            'permission'=>!empty($v['public'])?'public_registration':'not_determined'));
    }
    $formCount=$summary['forms_discovered'];
    // Existing forms are inventoried statically, never submitted. Count ALL, even when storage is truncated.
    $reasonCounts['form_not_submitted']=($reasonCounts['form_not_submitted']??0)+$formCount;
    foreach((array)($s['frontend8']['forms']??array()) as $form){
        if(!is_array($form))continue;
        if(count($backlog)>=10000)break;
        $file=(string)($form['file']??'');
        $backlog[]=array('priority'=>2,'kind'=>'form','name'=>(string)($form['action']??'not_declared'),
            'method'=>(string)($form['method']??'UNKNOWN'),'component'=>hsa98_component($file),
            'file'=>$file,'line'=>(int)($form['line']??0),
            'reason'=>'form_not_submitted','permission'=>'unknown_nonce_and_authorization');
    }
    // Order by priority, then cap the exported examples, never the counters.
    usort($backlog,function($a,$b){return ($a['priority']<=>$b['priority'])?:strcmp((string)$a['component'],(string)$b['component']);});
    $summary['backlog_total']=array_sum($reasonCounts);
    $backlog=array_slice($backlog,0,300);
    $summary['backlog_stored']=count($backlog);
    $summary['rest_handler_rows_stored']=count($handlers);
    $summary['rest_handler_rows_truncated']=max(0,$summary['registered_rest_method_entries']-count($handlers));
    $summary['file_index_complete']=$summary['files_read']===$summary['files_indexed'];
    $engine=(array)($s['engine_plan']['jobs']??array());
    $queued=count($engine);$processed=count($results);
    $checks=array(
      array('name'=>'scan_completed','passed'=>($s['phase']??'')==='complete' && !empty($s['done'])),
      array('name'=>'queue_complete','passed'=>$queued===$processed && $queued>0),
      array('name'=>'file_index_complete','passed'=>$summary['file_index_complete']),
      array('name'=>'evidence_hashes_valid','passed'=>$evidence['invalid']===0 && $evidence['missing']===0 && $evidence['duplicates']===0),
      array('name'=>'cleanup_not_failed','passed'=>!in_array('failed',array_column($results,'cleanup'),true))
    );
    $technical=true;foreach($checks as $check)if(!$check['passed'])$technical=false;
    $components=array_values($indexes);
    usort($components,function($a,$b){return ($b['state_changing_not_tested']+$b['hooks_not_tested'])<=>($a['state_changing_not_tested']+$a['hooks_not_tested']);});
    return array('version'=>'10.0.0','status'=>$technical?'technical_checks_passed':'technical_checks_failed',
      'security_coverage'=>'incomplete','summary'=>$summary,'evidence'=>$evidence,'checks'=>$checks,
      'components'=>$components,'rest_handlers'=>$handlers,'priority_backlog'=>$backlog,'backlog_reasons'=>$reasonCounts,
      'invalid_evidence_ids'=>array_slice($invalidIds,0,30),
      'explanation'=>'REAL HOOK 5/6: HTTP POST i ślad dispatch istniejącego hooka nie dowodzą wykorzystania ani wykonania konkretnego callbacku. REAL 1/6 oznacza wyłącznie potwierdzone wykonanie dokładnego callbacku GET. Nie jest to dowód odporności ani podatności. Obserwacja HTTP na trasie GET ≠ wykonany handler ani potwierdzenie odporności. Laboratoria syntetyczne nie podnoszą pokrycia realnych callbacków. Zapisane testy są wyłącznie dowodami wykonanych scenariuszy. Nie analizowano hostingu.',
      'limitations'=>array('Rejestr pokazuje callbacki obecne w jednym żądaniu administracyjnym; dynamicznie dodawane później mogą nie być widoczne.',
        'Rzeczywiste AJAX/admin-post: maksymalnie 3 jawnie zatwierdzone anonimowe POST, tylko dla nazw sugerujących odczyt. Pozostałe hooki, formularze, shortcode, widgety i bloki bez dowodów aktywnych prób.',
        'Dla GET liczone są obserwacje HTTP dla trasy, a nie autoryzacja każdego handlera i wariantu danych.',
        'Dla metod modyfikujących nie prowadzono prób na rzeczywistych handlerach innych komponentów.',
        'Ocena końcowa dotyczy spójności lokalnego raportu, nie jest certyfikatem bezpieczeństwa.'));
}
