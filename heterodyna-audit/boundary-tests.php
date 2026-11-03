<?php
if (!defined('ABSPATH')) { exit; }
/**
 * Heterodyna v6.8 / ZIP 5/12 — narrowly scoped behavioral checks.
 * No remote hosts are contacted. Every application request stays on the
 * current WordPress origin, with redirects disabled. Never classify a
 * negative probe as proof that the whole application is secure.
 */
add_action('rest_api_init', function () {
    register_rest_route('hsa-audit/v1', '/ssrf-canary', array(
        'methods'=>'GET', 'permission_callback'=>'__return_true',
        'callback'=>function($request) {
            $token=(string)$request->get_param('key');
            if (!preg_match('/^[a-f0-9]{32}$/D',$token)) return new WP_Error('hsa_no_canary','Not found',array('status'=>404));
            $k='hsa68_'.substr(hash('sha256',$token),0,24);
            $v=get_transient($k);
            if ($v===false) return new WP_Error('hsa_no_canary','Not found',array('status'=>404));
            set_transient($k,(int)$v+1,120);
            return array('ok'=>true,'kind'=>'hsa_same_origin_canary');
        },
    ));
});
function hsa68_methods_get($methods) {
    return hsa66_methods_allow_get($methods);
}
function hsa68_plan($routes,$limit=8) {
    $limit=max(0,min(8,(int)$limit));
    $plan=array('redirect'=>array(),'ssrf'=>array(),'validation'=>array(), 'skipped'=>array(),
        'scope'=>'Bounded anonymous GET to same WordPress origin; no redirect following or external network',
        'limitations'=>'SSRF same-origin fetch is an observation, not proof of attacker-controlled network access. CSRF uses a disposable own draft and tests unauthenticated mutation, not a forged authenticated browser.');
    $preferred=array('redirect_to','redirect','return_url','return','next','destination','url','target','callback_url','uri','endpoint','source_url');
    $numeric=array('page','per_page','limit','offset','count','number');
    foreach ((array)$routes as $path=>$handlers) {
        if (!is_string($path) || !preg_match('~^/[A-Za-z0-9_./-]{1,240}$~D',$path) || strpos($path,'..')!==false || strpos($path,'//')!==false) continue;
        if (strpos($path,'/hsa-audit/v1/')===0) continue; // exclude own canary
        foreach((array)$handlers as $h) {
            if(!is_array($h)||!hsa68_methods_get($h['methods']??array()))continue;
            foreach((array)($h['args']??array()) as $p=>$a) {
                if(!is_string($p)||!preg_match('/^[a-z][A-Za-z0-9_]{0,40}$/D',$p)||!is_array($a)||!empty($a['required']))continue;
                $pl=strtolower($p);
                if(in_array($pl,$preferred,true)) {
                    if(count($plan['redirect'])<$limit) $plan['redirect'][]=array('path'=>$path,'parameter'=>$p);
                    if(count($plan['ssrf'])<$limit && in_array($pl,array('url','uri','endpoint','source_url','target','callback_url'),true))
                        $plan['ssrf'][]=array('path'=>$path,'parameter'=>$p);
                }
                if(in_array($pl,$numeric,true) && count($plan['validation'])<$limit && ($a['type']??'integer')==='integer')
                    $plan['validation'][]=array('path'=>$path,'parameter'=>$p);
            }
            break; // sample a single handler per route
        }
    }
    foreach(array('redirect','ssrf','validation') as $kind) {
        $unique=array();$arr=array();foreach($plan[$kind] as $item){$k=$item['path'].'|'.$item['parameter'];if(isset($unique[$k]))continue;$unique[$k]=true;$arr[]=$item;}
        $plan[$kind]=$arr;
    }
    return $plan;
}
function hsa68_jobs($plan) {
    $jobs=array(array('id'=>'BOUNDARY-OWN-DRAFT-WRITE','kind'=>'boundary_write_canary','method'=>'POST',
      'target'=>'/wp/v2/posts/{disposable_id}', 'expectation'=>'anonymous_cannot_modify_disposable_draft'));
    foreach(array('redirect','ssrf','validation') as $kind) {
        foreach((array)($plan[$kind]??array()) as $p) {
            $id='B68-'.strtoupper($kind).'-'.substr(hash('sha256',$p['path'].'|'.$p['parameter']),0,12);
            $jobs[]=array('id'=>$id,'kind'=>'boundary_'.$kind,'method'=>'GET','target'=>$p['path'],'parameter'=>$p['parameter'],
             'expectation'=>'bounded_observation_with_case_specific_oracle');
        }
    }
    return $jobs;
}
function hsa68_same_origin_url($path,$parameter,$value) {
    if (!preg_match('~^/[A-Za-z0-9_./-]{1,240}$~D',$path) || strpos($path,'..')!==false || strpos($path,'//')!==false ||
        !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,40}$/D',$parameter)) return false;
    $url=rest_url(ltrim($path,'/'));
    if(!hsa66_origin_ok($url))return false;
    $url=add_query_arg(array($parameter=>$value),$url);
    return hsa66_origin_ok($url)?$url:false;
}
/** Limited HTTP with no redirects, cookies or response-body persistence. */
function hsa68_http($url) {
    $out=array('executed'=>false,'status'=>0,'location'=>'','body_sha256'=>'','response_sha256'=>'','body_bytes'=>0,'error'=>'');
    if(!$url || !hsa66_origin_ok($url)) {$out['error']='outside_allowed_origin';return $out;}
    $r=wp_safe_remote_get($url,array('timeout'=>5,'redirection'=>0,'limit_response_size'=>8192,
      'cookies'=>array(),'sslverify'=>true,
      'headers'=>array('Accept'=>'application/json, text/html;q=0.8', 'User-Agent'=>'HeterodynaSecurityAudit/6.8 (authorized-staging-only)')));
    if(is_wp_error($r)){$out['error']='http_transport_error';return $out;}
    $out['executed']=true;$out['status']=(int)wp_remote_retrieve_response_code($r);
    $body=(string)wp_remote_retrieve_body($r);$out['body_sha256']=hash('sha256',$body);$out['response_sha256']=$out['body_sha256'];$out['body_bytes']=strlen($body);
    $out['location']=substr((string)wp_remote_retrieve_header($r,'location'),0,500);
    return $out;
}
/** Only an actual observed 3xx to our never-visited .invalid marker is a redirect finding. */
function hsa68_redirect_oracle($r,$expected) {
    if(empty($r['executed']))return array('verdict'=>'inconclusive','proof'=>'no_http_response','confirmed'=>false);
    $status=(int)$r['status'];$loc=(string)$r['location'];
    if($status>=300 && $status<400 && $loc!=='' && strpos($loc,$expected)===0) {
        return array('verdict'=>'confirmed_redirect_behavior','proof'=>'anonymous_external_redirect_location_header_matches_controlled_marker','confirmed'=>false);
    }
    if(in_array($status,array(401,403),true))return array('verdict'=>'observed_control','proof'=>'anonymous_access_denied','confirmed'=>false);
    return array('verdict'=>'probe_observation','proof'=>'external_redirect_not_observed_in_this_request','confirmed'=>false);
}
function hsa68_run_redirect($job) {
    $marker=bin2hex(random_bytes(8));
    $destination='https://hsa-audit.invalid/'.$marker;
    $url=hsa68_same_origin_url($job['target'],$job['parameter'],$destination);
    $r=hsa68_http($url);
    $d=hsa68_redirect_oracle($r,$destination);
    $r['location_sha256']=hash('sha256',(string)$r['location']);
    $r['location_host']=is_string($r['location'])?(string)wp_parse_url($r['location'],PHP_URL_HOST):'';
    unset($r['location']); // Raw Location may contain cookies, codes or other user data.
    return array('verdict'=>$d['verdict'],'proof'=>$d['proof'],'confirmed'=>$d['confirmed'],'http'=>$r,
        'note'=>'External redirect behavior was verified from Location, but whether it is a security vulnerability depends on the route policy. The .invalid destination was not visited.');
}
function hsa68_run_ssrf($job) {
    $token=bin2hex(random_bytes(16));$key='hsa68_'.substr(hash('sha256',$token),0,24);
    $target=rest_url('hsa-audit/v1/ssrf-canary');
    $target=add_query_arg('key',$token,$target);
    if(!hsa66_origin_ok($target))return array('verdict'=>'inconclusive','proof'=>'canary_outside_allowed_origin','confirmed'=>false,'http'=>array());
    set_transient($key,0,120);
    try {
        $url=hsa68_same_origin_url($job['target'],$job['parameter'],$target);
        $r=hsa68_http($url);
        $hits=get_transient($key); // WP HTTP call may have triggered our same-origin canary route
    } finally { delete_transient($key); }
    if(is_array($r))unset($r['location']);
    $hits=is_numeric($hits)?(int)$hits:0;
    return array('verdict'=>$hits>0?'server_fetch_observed':(!empty($r['executed'])?'probe_observation':'inconclusive'),
        'proof'=>$hits>0?'one_time_same_origin_canary_called_by_target_handler':'same_origin_fetch_not_observed',
        'confirmed'=>false,'http'=>$r,'canary_hits'=>$hits,
        'note'=>'Same-origin fetch demonstrates application-side URL retrieval, NOT arbitrary external SSRF or internal-network access. No external address was contacted.');
}
function hsa68_run_validation($job) {
    $url=hsa68_same_origin_url($job['target'],$job['parameter'],'not_an_integer_hsa68');
    $r=hsa68_http($url);unset($r['location']);$status=(int)($r['status']??0);
    $verdict=empty($r['executed'])?'inconclusive':($status===400?'observed_control':(in_array($status,array(401,403),true)?'observed_control':'probe_observation'));
    return array('verdict'=>$verdict,'proof'=>empty($r['executed'])?'no_http_response':($status===400?'invalid_integer_rejected_http_400':'invalid_integer_response_observed_not_proof_of_exploit'),
       'confirmed'=>false,'http'=>$r,'note'=>'Input type behavior only; 2xx is not proof of unsafe validation or exploitable vulnerability.');
}
/** Internal REST dispatch to disposable WordPress draft, not a browser CSRF proof. */
function hsa68_run_write_canary() {
    if(!function_exists('wp_insert_post') || !function_exists('rest_do_request'))
        return array('verdict'=>'inconclusive','proof'=>'wordpress_test_api_unavailable','confirmed'=>false,'http'=>array(),'cleanup'=>'not_created');
    $id=0;$original_user=get_current_user_id();$marker='hsa68_'.bin2hex(random_bytes(12));
    $out=array('verdict'=>'inconclusive','proof'=>'not_run','confirmed'=>false,'http'=>array(),'cleanup'=>'not_created');
    try {
        $id=wp_insert_post(array('post_title'=>'HSA temporary authorization canary','post_content'=>$marker,
            'post_status'=>'draft','post_type'=>'post','post_author'=>$original_user),true);
        if(is_wp_error($id)||!$id) { $out['proof']='canary_create_failed';return $out; }
        wp_set_current_user(0);
        $req=new WP_REST_Request('POST','/wp/v2/posts/'.$id);
        $req->set_param('title','HSA unauthorized change '.bin2hex(random_bytes(6)));
        $response=rest_do_request($req);
        $status=(int)$response->get_status();
        wp_set_current_user($original_user);
        clean_post_cache($id);
        $after=get_post($id);
        $mutated=$after && $after->post_title!=='HSA temporary authorization canary';
        $out['http']=array('executed'=>false,'status'=>$status,'internal_dispatch'=>true);
        if($mutated) {$out['verdict']='confirmed_vulnerability';$out['proof']='anonymous_internal_rest_mutated_disposable_draft';$out['confirmed']=true;}
        elseif(in_array($status,array(401,403,404),true)) {$out['verdict']='observed_control';$out['proof']='anonymous_write_denied_and_draft_unchanged';}
        else {$out['verdict']='probe_observation';$out['proof']='draft_unchanged_for_this_anonymous_write_attempt';}
        $out['note']='Tests unauthenticated write authorization on the built-in WordPress draft handler. NOT an end-to-end forged logged-in browser / CSRF test.';
    } catch(Throwable $e) {$out['verdict']='inconclusive';$out['proof']='wordpress_internal_dispatch_exception_'.get_class($e);}
    finally {
        wp_set_current_user($original_user);
        if(is_int($id)&&$id>0) {
            wp_delete_post($id,true);
            $out['cleanup']=get_post($id)?'failed':'confirmed';
        }
    }
    return $out;
}
function hsa68_execute($job) {
    $k=(string)($job['kind']??'');
    switch($k) {
        case 'boundary_redirect':return hsa68_run_redirect($job);
        case 'boundary_ssrf':return hsa68_run_ssrf($job);
        case 'boundary_validation':return hsa68_run_validation($job);
        case 'boundary_write_canary':return hsa68_run_write_canary();
    }
    return array('verdict'=>'inconclusive','proof'=>'unsupported_boundary_kind','confirmed'=>false,'http'=>array());
}
function hsa68_summary($plan,$engine_results,$enabled=true) {
    $r=array();$counts=array();$completed=0;$network=0;
    foreach((array)$engine_results as $item) {
        if(strpos((string)($item['kind']??''),'boundary_')!==0)continue;
        $completed++;$v=(string)($item['verdict']??'inconclusive');$counts[$v]=($counts[$v]??0)+1;
        if(!empty($item['executed']))$network++;
        $r[]=array('id'=>$item['id'],'kind'=>$item['kind'],'path'=>$item['target'],'parameter'=>$item['parameter']??'',
           'verdict'=>$v,'proof'=>$item['proof']??'','http_status'=>$item['http']['status']??0,
           'canary_hits'=>$item['canary_hits']??null,'cleanup'=>$item['cleanup']??'not_applicable','evidence_sha256'=>$item['evidence_sha256']??'');
    }
    return array('summary'=>array('planned'=>$enabled?count(hsa68_jobs($plan)):0,'processed'=>$completed,'network_requests'=>$network,
        'families'=>array_map('count',array_intersect_key($plan,array_flip(array('redirect','ssrf','validation')))),
        'verdicts'=>$counts,'limitations'=>$plan['limitations']??''),'items'=>$r);
}
