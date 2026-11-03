<?php
if (!defined('ABSPATH')) { exit; }
/**
 * 6.4: AuthZ verification restricted to this WordPress installation.
 * A disposable subscriber is used only for one case at a time. No passwords,
 * cookies, response bodies, or source code are exported. Third-party REST
 * permission callbacks are probed, but their handlers are NOT invoked.
 */
function hsa_authz_plan($entry_map, $limit = 12) {
    $limit=max(0,min(20,(int)$limit)); $selected=array(); $seen=array();
    $paths=(array)($entry_map['rest']??array());
    // Prioritize external plugin namespaces; still include core for coverage.
    uksort($paths, function($a,$b) {
        $aCore=(strpos($a,'/wp/')===0 || strpos($a,'/wp-')===0);
        $bCore=(strpos($b,'/wp/')===0 || strpos($b,'/wp-')===0);
        return ($aCore===$bCore) ? strcmp($a,$b) : ($aCore?1:-1);
    });
    foreach($paths as $path=>$handlers) {
        if (count($selected)>=$limit) break;
        if (!is_string($path) || !preg_match('~^/[A-Za-z0-9_./-]{1,300}$~D',$path)) continue;
        if (isset($seen[$path])) continue;
        foreach((array)$handlers as $idx=>$h) {
            if(!in_array('GET',(array)($h['methods']??array()),true))continue;
            if(($h['permission_declaration']??'')!=='declared_callback')continue;
            $selected[]=array('id'=>'AUTHZ-CALLBACK-'.substr(hash('sha256',$path.'#'.$idx),0,14),
                'kind'=>'authz_callback','target'=>$path,'handler_index'=>(int)$idx,
                'method'=>'GET','expectation'=>'compare_permission_decisions_not_handler_exploit');
            $seen[$path]=true;break;
        }
    }
    return $selected;
}
function hsa_authz_decision($ret) {
    if (function_exists('is_wp_error') && is_wp_error($ret)) return array('decision'=>'denied','detail'=>'wp_error_'.sanitize_key($ret->get_error_code()));
    if($ret===false || $ret===null) return array('decision'=>'denied','detail'=>$ret===null?'null':'false');
    return array('decision'=>'allowed','detail'=>'non_false_non_null');
}
function hsa_authz_temporary_user() {
    if(!function_exists('wp_insert_user'))return array('id'=>0,'reason'=>'wp_insert_user_missing');
    $tag=bin2hex(random_bytes(6));
    $user=wp_insert_user(array('user_login'=>'hsa_audit_'.$tag,'user_pass'=>wp_generate_password(40,true,true),
        'user_email'=>'hsa-'.$tag.'@example.invalid','role'=>'subscriber',
        'display_name'=>'HSA Audit Temporary Subscriber'));
    if(is_wp_error($user) || !$user)return array('id'=>0,'reason'=>'subscriber_creation_failed');
    $id=(int)$user;
    update_user_meta($id,'_hsa_audit_temporary',1);
    // A backup cleanup in case the PHP worker fatals. WP-Cron must be enabled.
    wp_schedule_single_event(time()+3600,'hsa_authz_cleanup_user',array($id));
    return array('id'=>$id,'reason'=>'created');
}
function hsa_authz_cleanup_user($id) {
    $id=(int)$id;
    if($id<=0 || (string)get_user_meta($id,'_hsa_audit_temporary',true)!=='1')return false;
    $user=get_userdata($id);
    if(!$user || strpos((string)$user->user_login,'hsa_audit_')!==0)return false;
    if(!function_exists('wp_delete_user'))require_once ABSPATH.'wp-admin/includes/user.php';
    $deleted=wp_delete_user($id);
    if($deleted)wp_clear_scheduled_hook('hsa_authz_cleanup_user',array($id));
    return (bool)$deleted;
}
add_action('hsa_authz_cleanup_user','hsa_authz_cleanup_user');
/** Run a permission callback only. It may have its own side effects. */
function hsa_authz_callback_for_role($callback, $path, $uid) {
    $prior=get_current_user_id();$outputLevel=ob_get_level();
    try {
        wp_set_current_user((int)$uid);
        $req=new WP_REST_Request('GET',$path);
        ob_start(); // Third-party callback output must not corrupt the AJAX JSON envelope.
        $result=call_user_func($callback,$req);
        return hsa_authz_decision($result);
    } catch (Throwable $e) {
        return array('decision'=>'error','detail'=>'exception_'.get_class($e));
    } finally {
        while(ob_get_level()>$outputLevel)ob_end_clean();
        wp_set_current_user($prior);
    }
}
function hsa_authz_callback_probe($job) {
    $out=array('kind'=>'callback_only','target'=>$job['target']??'',
        'status'=>'inconclusive','anonymous'=>array(),'subscriber'=>array(),'administrator'=>array(),
        'cleanup'=>'not_created','executed'=>false,'tested_roles'=>0,
        'interpretation'=>'Callback uprawnień bez wykonania właściwego handlera. Nie dowodzi podatności.');
    $path=(string)($job['target']??'');$idx=(int)($job['handler_index']??-1);
    if(!preg_match('~^/[A-Za-z0-9_./-]{1,300}$~D',$path))return $out;
    $routes=rest_get_server()->get_routes();
    $handler=$routes[$path][$idx]??null;
    if(!is_array($handler) || !in_array('GET',hsa_map_methods($handler['methods']??array()),true))return $out;
    $callback=$handler['permission_callback']??null;
    if(!is_callable($callback))return $out;
    $temp=hsa_authz_temporary_user();
    if(!$temp['id']) { $out['interpretation']='Nie udało się utworzyć testowego subskrybenta.';return $out; }
    try {
        $out['anonymous']=hsa_authz_callback_for_role($callback,$path,0);$out['tested_roles']++;
        $out['subscriber']=hsa_authz_callback_for_role($callback,$path,$temp['id']);$out['tested_roles']++;
        $out['administrator']=hsa_authz_callback_for_role($callback,$path,get_current_user_id());$out['tested_roles']++;
        $out['executed']=true;
        $vals=array($out['anonymous']['decision'],$out['subscriber']['decision'],$out['administrator']['decision']);
        if(in_array('error',$vals,true))$out['status']='inconclusive';
        elseif($out['anonymous']['decision']==='denied' && $out['subscriber']['decision']==='denied' && $out['administrator']['decision']==='allowed')$out['status']='role_restriction_observed';
        elseif($out['anonymous']['decision']==='allowed')$out['status']='anonymous_permission_allowed_review';
        else $out['status']='other_permission_pattern';
        $out['interpretation']='Wykonano tylko permission_callback dla trzech kontekstów. Brak testu handlera, brak podstaw do statusu potwierdzonej podatności.';
    } finally {
        $out['cleanup']=hsa_authz_cleanup_user($temp['id'])?'confirmed':'failed';
    }
    return $out;
}
/** Internal REST dispatch performs the real core GET handler for a disposable draft. */
function hsa_authz_draft_dispatch($path, $uid, $marker) {
    $prior=get_current_user_id();$outputLevel=ob_get_level();
    try {
        wp_set_current_user((int)$uid);
        $req=new WP_REST_Request('GET',$path);
        $req->set_param('context','edit');
        ob_start();
        $response=rest_do_request($req);
        if(is_wp_error($response))return array('executed'=>true,'status'=>0,'marker_seen'=>false,'error'=>$response->get_error_code());
        if(!is_object($response) || !method_exists($response,'get_status'))return array('executed'=>false,'status'=>0,'marker_seen'=>false,'error'=>'unexpected_response');
        $body=wp_json_encode($response->get_data());
        return array('executed'=>true,'status'=>(int)$response->get_status(),
            'marker_seen'=>is_string($body)&&strpos($body,$marker)!==false,'error'=>'');
    } catch(Throwable $e){
        return array('executed'=>false,'status'=>0,'marker_seen'=>false,'error'=>'exception_'.get_class($e));
    } finally {
        while(ob_get_level()>$outputLevel)ob_end_clean();
        wp_set_current_user($prior);
    }
}
/** Pure proof oracle: own/private marker accessible by an unauthorized role. */
function hsa_authz_draft_verdict($responses) {
    $admin=$responses['administrator']??array();$anon=$responses['anonymous']??array();$subscriber=$responses['subscriber']??array();
    if(empty($admin['executed']) || empty($admin['marker_seen']))return 'inconclusive';
    if(!empty($anon['marker_seen']) || !empty($subscriber['marker_seen']))return 'confirmed_vulnerability';
    if(empty($anon['executed']) || empty($subscriber['executed']))return 'inconclusive';
    if(in_array((int)($anon['status']??0),array(401,403,404),true) &&
        in_array((int)($subscriber['status']??0),array(401,403,404),true))return 'observed_control';
    return 'inconclusive';
}
function hsa_authz_draft_canary() {
    $out=array('kind'=>'draft_role_matrix','status'=>'inconclusive','responses'=>array(),
        'cleanup'=>array('post'=>'not_created','user'=>'not_created'),'executed'=>false,
        'confirmation'=>'none','roles_tested'=>0,'interpretation'=>'Test wyłącznie kontrolowanego wpisu WordPress.');
    if(!current_user_can('edit_posts') || !current_user_can('delete_posts') || !current_user_can('create_users')) {
        $out['interpretation']='Administrator nie ma wymaganych uprawnień do utworzenia obiektów testowych.';return $out;
    }
    $temp=hsa_authz_temporary_user();
    if(!$temp['id']){$out['interpretation']='Nie utworzono subskrybenta.';return $out;}
    $postId=0;$adminId=get_current_user_id();
    try {
        $marker='HSA_AUTHZ_PRIVATE_'.strtoupper(bin2hex(random_bytes(14)));
        $post=wp_insert_post(array('post_type'=>'post','post_status'=>'draft','post_title'=>'HSA authorization canary',
            'post_content'=>$marker,'post_author'=>$adminId),true);
        if(is_wp_error($post)||!$post) {$out['interpretation']='Nie utworzono szkicu testowego.';return $out;}
        $postId=(int)$post;
        $path='/wp/v2/posts/'.$postId;
        foreach(array('administrator'=>$adminId,'anonymous'=>0,'subscriber'=>$temp['id']) as $role=>$uid) {
            $out['responses'][$role]=hsa_authz_draft_dispatch($path,$uid,$marker);
            $out['roles_tested']++;
        }
        $out['executed']=true;
        $out['status']=hsa_authz_draft_verdict($out['responses']);
        if($out['status']==='confirmed_vulnerability')$out['confirmation']='exact_private_marker_observed_by_unauthorized_role';
        elseif($out['status']==='observed_control')$out['confirmation']='unauthorized_roles_denied_private_draft';
        $out['interpretation']='Wykonano REST GET na prywatnym szkicu jako administrator, anonimowy i subskrybent; porównano dokładny losowy znacznik. Odpowiedzi i treść znacznika nie są eksportowane.';
    } catch(Throwable $e){$out['status']='inconclusive';$out['interpretation']='Błąd '.get_class($e);}
    finally {
        if($postId) {
            $deleted=wp_delete_post($postId,true);
            $out['cleanup']['post']=$deleted!==false && get_post($postId)===null?'confirmed':'failed';
        }
        $out['cleanup']['user']=hsa_authz_cleanup_user($temp['id'])?'confirmed':'failed';
        if($out['cleanup']['post']==='failed'||$out['cleanup']['user']==='failed')$out['interpretation'].=' OSTRZEŻENIE: usuwanie obiektu testowego nie zostało potwierdzone.';
    }
    return $out;
}

function hsa_authz_summary($results) {
    $counts=array();$roleCalls=0;$cleanFailed=0;
    foreach((array)$results as $r){
        $v=(string)($r['verdict']??'inconclusive');$counts[$v]=($counts[$v]??0)+1;
        $roleCalls+=(int)($r['roles_tested']??0);
        if(($r['cleanup']??'')==='failed')$cleanFailed++;
    }
    return array('cases'=>count((array)$results),'role_calls'=>$roleCalls,'verdicts'=>$counts,
        'cleanup_failures'=>$cleanFailed,'limitations'=>'Obcy kod: wykonano wyłącznie permission_callback. Pełny handler GET uruchomiono tylko na izolowanym szkicu WordPress. Zmiana odpowiedzi callbacku nie dowodzi podatności.');
}
