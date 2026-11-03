<?php
if (!defined('ABSPATH')) { exit; }
/** Stage II 4/8. Four anonymous HTTP POST tests against ephemeral, synthetic AJAX/admin-post fixtures.
 * Third-party handlers are INVENTORIED only; never execute unknown callbacks with mutating data.
 */
function hsa90_fixture_data($session,$secret) {
    if (!is_string($session) || !preg_match('/^[a-f0-9]{24}$/D',$session) ||
        !is_string($secret) || !preg_match('/^[a-f0-9]{48}$/D',$secret)) return false;
    $row=get_transient('hsa90_'.$session);
    if (!is_array($row) || !isset($row['secret'],$row['marker']) ||
        !is_string($row['secret']) || !hash_equals($row['secret'],$secret)) return false;
    return $row;
}
function hsa90_fixture_endpoint($protected=false) {
    if (($_SERVER['REQUEST_METHOD']??'')!=='POST') {
        wp_send_json(array('fixture'=>'synthetic_only','error'=>'method_not_allowed'),405);
        return;
    }
    $session=isset($_POST['hsa_session']) && is_string($_POST['hsa_session']) ? $_POST['hsa_session'] : '';
    $secret=isset($_POST['hsa_secret']) && is_string($_POST['hsa_secret']) ? $_POST['hsa_secret'] : '';
    $row=hsa90_fixture_data($session,$secret);
    if ($row===false) { wp_send_json(array('fixture'=>'synthetic_only','error'=>'fixture_unavailable'),404); return; }
    if ($protected) { wp_send_json(array('fixture'=>'synthetic_only','error'=>'access_denied'),403); return; }
    // Deliberately open to the anonymous synthetic token, NEVER expose WordPress data.
    wp_send_json(array('fixture'=>'synthetic_only','marker'=>$row['marker']),200);
}
function hsa90_ajax_weak() { hsa90_fixture_endpoint(false); }
function hsa90_ajax_guarded() { hsa90_fixture_endpoint(true); }
function hsa90_post_weak() { hsa90_fixture_endpoint(false); }
function hsa90_post_guarded() { hsa90_fixture_endpoint(true); }
if (function_exists('add_action')) {
    add_action('wp_ajax_nopriv_hsa90_weak','hsa90_ajax_weak');
    add_action('wp_ajax_nopriv_hsa90_guarded','hsa90_ajax_guarded');
    add_action('admin_post_nopriv_hsa90_weak','hsa90_post_weak');
    add_action('admin_post_nopriv_hsa90_guarded','hsa90_post_guarded');
}
function hsa90_jobs() {
    return array(
        array('id'=>'AJAX90-SYNTHETIC-PAIR','kind'=>'ajax90_pair','method'=>'2x POST','target'=>'/wp-admin/admin-ajax.php (synthetic only)','expectation'=>'synthetic_marker_visible_only_in_weak_fixture'),
        array('id'=>'ADMINPOST90-SYNTHETIC-PAIR','kind'=>'adminpost90_pair','method'=>'2x POST','target'=>'/wp-admin/admin-post.php (synthetic only)','expectation'=>'synthetic_marker_visible_only_in_weak_fixture')
    );
}
/** Pure function: network errors cannot turn into a PASS; 2xx alone is insufficient. */
function hsa90_oracle($weak,$guarded,$cleanup) {
    if (empty($weak['executed']) || empty($guarded['executed']))
        return array('status'=>'inconclusive','proof'=>'http_not_completed','pass'=>false);
    $w=(int)($weak['status']??0)===200 && !empty($weak['exact_marker']);
    $g=(int)($guarded['status']??0)===403 && empty($guarded['exact_marker']);
    if (!$cleanup) return array('status'=>'fail','proof'=>'fixture_cleanup_unverified','pass'=>false);
    return array('status'=>$w && $g?'pass':'fail',
        'proof'=>$w && $g?'synthetic_open_detected_and_guard_denied':'synthetic_expectation_failed','pass'=>$w && $g);
}
function hsa90_http($surface,$variant,$session,$secret,$marker) {
    $out=array('executed'=>false,'status'=>0,'response_sha256'=>'','exact_marker'=>false,'error'=>'','response_bytes'=>0);
    if (!in_array($surface,array('ajax','post'),true) || !in_array($variant,array('weak','guarded'),true)) {
        $out['error']='invalid_fixture';return $out;
    }
    $url=admin_url($surface==='ajax'?'admin-ajax.php':'admin-post.php');
    if (!function_exists('hsa_rest_same_origin') || !hsa_rest_same_origin($url)) {
        $out['error']='origin_mismatch'; return $out;
    }
    $response=wp_safe_remote_post($url,array('timeout'=>7,'redirection'=>0,'sslverify'=>true,
        'limit_response_size'=>4096,'cookies'=>array(),
        'headers'=>array('Accept'=>'application/json','Cache-Control'=>'no-store','User-Agent'=>'HeterodynaAudit/9.0 synthetic lab'),
        'body'=>array('action'=>'hsa90_'.$variant,'hsa_session'=>$session,'hsa_secret'=>$secret)));
    if (is_wp_error($response)) { $out['error']=substr((string)$response->get_error_code(),0,60);return $out; }
    $body=(string)wp_remote_retrieve_body($response);
    $out['executed']=true; $out['status']=(int)wp_remote_retrieve_response_code($response);
    $out['response_sha256']=hash('sha256',$body); $out['response_bytes']=strlen($body);
    $decoded=json_decode($body,true);
    $out['exact_marker']=is_array($decoded) && ($decoded['fixture']??'')==='synthetic_only' &&
        is_string($decoded['marker']??null) && hash_equals($marker,$decoded['marker']);
    return $out;
}
function hsa90_execute($surface) {
    $out=array('surface'=>$surface,'weak'=>array(),'guarded'=>array(),'http_requests'=>0,
        'cleanup'=>'not_created','oracle'=>array('status'=>'inconclusive','proof'=>'not_started','pass'=>false));
    if (!in_array($surface,array('ajax','post'),true)) return $out;
    if (!current_user_can('manage_options')) { $out['oracle']['proof']='admin_capability_required';return $out; }
    $session=bin2hex(random_bytes(12));$secret=bin2hex(random_bytes(24));
    $marker='HSA90_'.strtoupper(bin2hex(random_bytes(24)));
    $created=set_transient('hsa90_'.$session,array('secret'=>$secret,'marker'=>$marker),90);
    if (!$created) { $out['oracle']['proof']='fixture_create_failed';return $out; }
    try {
        $out['weak']=hsa90_http($surface,'weak',$session,$secret,$marker);
        $out['guarded']=hsa90_http($surface,'guarded',$session,$secret,$marker);
        $out['http_requests']=(int)!empty($out['weak']['executed'])+(int)!empty($out['guarded']['executed']);
    } catch (Throwable $e) { $out['error']='exception_'.get_class($e); }
    finally {
        delete_transient('hsa90_'.$session);
        $out['cleanup']=get_transient('hsa90_'.$session)===false?'confirmed':'failed';
    }
    $out['oracle']=hsa90_oracle($out['weak'],$out['guarded'],$out['cleanup']==='confirmed');
    return $out;
}
/** Registered hook inventory, with every third-party handler explicitly marked untested. */
function hsa90_inventory($map) {
    $items=array();$nopriv=0;$auth=0;
    foreach((array)($map['entries']??array()) as $entry) {
        if(($entry['kind']??'')!=='hook') continue;
        $hook=(string)($entry['name']??'');
        if (!preg_match('/^(wp_ajax_|admin_post_)/',$hook) || preg_match('/^((wp_ajax|admin_post)_nopriv_)?hsa90_/', $hook)) continue;
        if (strpos($hook,'hsa90_')!==false || strpos($hook,'hsa92_')!==false) continue;
        $open=strpos($hook,'_nopriv_')!==false;
        if ($open)$nopriv++;else $auth++;
        $source=$entry['source']??array();
        $items[]=array('hook'=>$hook,'public_registration'=>$open,'file'=>(string)($source['file']??''),
            'line'=>(int)($source['line']??0),'component'=>function_exists('hsa_map_component_for_path')?hsa_map_component_for_path((string)($source['file']??'')):'unknown',
            'status'=>'not_executed_requires_safe_test_contract');
    }
    return array('registered_count'=>count($items),'public_hooks'=>$nopriv,'authenticated_hooks'=>$auth,
        'untested_count'=>count($items),'items'=>$items);
}
function hsa90_record($job,$out) {
    $oracle=$out['oracle']??array();$weak=$out['weak']??array();$guard=$out['guarded']??array();
    return array('verdict'=>($oracle['status']??'inconclusive')==='pass'?'acceptance_pass':
        (($oracle['status']??'')==='fail'?'acceptance_fail':'inconclusive'),
        'proof'=>(string)($oracle['proof']??'not_executed'),
        'executed'=>!empty($out['http_requests']),'http_requests'=>(int)$out['http_requests'],
        'http'=>array('executed'=>!empty($weak['executed']),'status'=>(int)($weak['status']??0),
            'response_sha256'=>(string)($weak['response_sha256']??'')),
        'ajax90'=>array('surface'=>$out['surface'],'weak_http'=>(int)($weak['status']??0),
            'guarded_http'=>(int)($guard['status']??0),'weak_marker'=>!empty($weak['exact_marker']),
            'guarded_marker'=>!empty($guard['exact_marker']), 'weak_sha256'=>$weak['response_sha256']??'',
            'guarded_sha256'=>$guard['response_sha256']??'', 'weak_error'=>$weak['error']??'',
            'guarded_error'=>$guard['error']??'', 'status'=>$oracle['status']??'inconclusive'),
        'cleanup'=>$out['cleanup'],'confirmed_vulnerability'=>false,
        'explanation'=>'Synthetic anonymous WordPress admin-ajax/admin-post POST only; third-party handlers not invoked.');
}
function hsa90_summary($map,$results,$enabled) {
    $inventory=hsa90_inventory($map);$items=array();$http=0;$failed=0;$cleanup=0;
    foreach((array)$results as $r) {
        if(!in_array(($r['kind']??''),array('ajax90_pair','adminpost90_pair'),true))continue;
        $d=$r['ajax90']??array();
        $items[]=array('surface'=>$d['surface']??'', 'id'=>$r['id']??'','status'=>$d['status']??'inconclusive',
            'weak_http'=>(int)($d['weak_http']??0),'guarded_http'=>(int)($d['guarded_http']??0),
            'weak_marker'=>!empty($d['weak_marker']),'guarded_marker'=>!empty($d['guarded_marker']),
            'weak_sha256'=>$d['weak_sha256']??'','guarded_sha256'=>$d['guarded_sha256']??'',
            'cleanup'=>$r['cleanup']??'not_executed','evidence_sha256'=>$r['evidence_sha256']??'');
        $http+=(int)($r['http_requests']??0);
        if(($d['status']??'')!=='pass')$failed++;
        if(($r['cleanup']??'')==='failed')$cleanup++;
    }
    return array('enabled'=>(bool)$enabled,'planned'=>$enabled?2:0,'executed'=>count($items),
        'external_http'=>$http,'acceptance_failures'=>$failed,'cleanup_failures'=>$cleanup,
        'acceptance_pass'=>$enabled && count($items)===2 && $http===4 && $failed===0 && $cleanup===0,
        'fixtures'=>$items,'inventory'=>$inventory,
        'scope'=>'Synthetic AJAX/admin-post only; registered third-party callbacks are not executed.');
}
