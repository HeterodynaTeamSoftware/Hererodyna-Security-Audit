<?php
if (!defined('ABSPATH')) { exit; }
/** Real WP core REST write check. Never accepts a target URL, post ID or payload from the client. */
function hsa150_snapshot($id) {
    $p=get_post($id);
    if(!$p)return null;
    return hash('sha256',json_encode(array($p->post_title,$p->post_content,$p->post_status,$p->post_author,$p->post_name,$p->post_type)));
}
function hsa150_cleanup($journal) {
    $id=(int)($journal['id']??0);
    if(!$id)return array('confirmed'=>false,'reason'=>'fixture_id_not_recorded');
    $p=get_post($id);
    if(!$p)return array('confirmed'=>true,'reason'=>'already_absent');
    if($p->post_type!==($journal['post_type']??'post')||$p->post_name!==($journal['slug']??'')||(int)$p->post_author!==(int)($journal['user']??0))
        return array('confirmed'=>false,'reason'=>'ownership_mismatch','fixture_id'=>$id);
    wp_delete_post($id,true);
    return array('confirmed'=>get_post($id)===null,'fixture_id'=>$id);
}
function hsa150_run($adapter=null) {
    $type=$adapter['post_type']??'post';
    $routeBase=$adapter['route_base']??'/wp/v2/posts';
    $editCap=$adapter['edit_cap']??'edit_posts';
    $dispatch=$adapter['dispatch']??'rest_do_request';
    if(!current_user_can('manage_options')||!current_user_can($editCap))return array('status'=>'forbidden');
    $user=get_current_user_id();
    $token=strtolower(wp_generate_password(24,false,false));
    if(!preg_match('/^[a-z0-9]{24}$/D',$token))return array('status'=>'invalid_random');
    $journal=array('id'=>0,'slug'=>'hsa150-'.$token,'user'=>$user,'started'=>time(),'post_type'=>$type);
    // Persistent journal doubles as a site-wide lock. Never overwrite a prior run.
    if(!add_option('hsa150_pending',$journal,'',false))return array('status'=>'pending_cleanup_or_running');
    $out=array('status'=>'inconclusive','scope'=>'internal_core_rest_post_title_only','transport'=>'in_process_not_http',
        'third_party_findings_confirmed'=>0,'anonymous'=>array(),'authorized'=>array(),'cleanup'=>array('confirmed'=>false),
        'started'=>gmdate('c'),'fixture_id'=>0);
    $id=0;$creationReturned=false;
    try {
        $id=wp_insert_post(array('post_type'=>$type,'post_status'=>'draft','post_author'=>$user,
            'post_name'=>$journal['slug'],'post_title'=>'HSA disposable baseline '.$token,'post_content'=>''),true);
        $creationReturned=true;
        if(is_wp_error($id)||!$id){$id=0;$out['status']='fixture_creation_failed';}
        else {
            $id=(int)$id;$journal['id']=$id;$out['fixture_id']=$id;
            update_option('hsa150_pending',$journal,false);
            if(get_option('hsa150_pending')!==$journal)throw new RuntimeException('Journal write failed');
            $p=get_post($id);
            if(!$p||$p->post_type!==$type||$p->post_status!=='draft'||$p->post_name!==$journal['slug']||(int)$p->post_author!==$user)
                throw new RuntimeException('Fixture modified by hooks');
            $out['route']=$routeBase.'/'.$id;
            $before=hsa150_snapshot($id);$out['before_sha256']=$before;
            wp_set_current_user(0);
            $request=new WP_REST_Request('POST',$out['route']);
            $request->set_param('title','HSA anonymous '.$token);
            $response=call_user_func($dispatch,$request);
            $status=(int)$response->get_status();$after=hsa150_snapshot($id);
            $p=get_post($id);$effect=$p&&$p->post_title==='HSA anonymous '.$token;
            $out['anonymous']=array('user_id'=>0,'http'=>$status,'before_sha256'=>$before,'after_sha256'=>$after,
                'unchanged'=>$before===$after,'marker_written'=>(bool)$effect,'denied'=>in_array($status,array(401,403),true));
            wp_set_current_user($user);
            $request=new WP_REST_Request('POST',$out['route']);
            $request->set_param('title','HSA authorized '.$token);
            $response=call_user_func($dispatch,$request);$status=(int)$response->get_status();$p=get_post($id);
            $positive=$status>=200&&$status<300&&$p&&$p->post_title==='HSA authorized '.$token;
            $out['authorized']=array('http'=>$status,'marker_written'=>(bool)$positive,'after_sha256'=>hsa150_snapshot($id));
            $out['status']=$effect?'unauthorized_fixture_write_observed':
                (($out['anonymous']['denied']&&$out['anonymous']['unchanged']&&$positive)?'tested_boundary_held':'inconclusive');
        }
    } catch(Throwable $e) { $out['status']='execution_error'; }
    finally {
        wp_set_current_user($user);
        try {
            $out['cleanup']=$id?hsa150_cleanup($journal):array('confirmed'=>$creationReturned,'reason'=>$creationReturned?'no_fixture_returned':'insert_interrupted_id_unknown');
            if($out['cleanup']['confirmed']){
                delete_option('hsa150_pending');
                if(get_option('hsa150_pending',null)!==null)$out['cleanup']=array('confirmed'=>false,'reason'=>'journal_removal_failed');
            }
        } catch(Throwable $e) { $out['cleanup']=array('confirmed'=>false,'reason'=>'cleanup_exception','fixture_id'=>$id); }
        $out['execution_status']=$out['status'];
        if(!$out['cleanup']['confirmed'])$out['status']='cleanup_failed';
        $out['user_restored']=get_current_user_id()===$user;
        if(!$out['user_restored'])$out['status']='user_restore_failed';
        $out['finished']=gmdate('c');
    }
    update_option('hsa150_last_result',$out,false);
    return $out;
}
add_action('wp_ajax_hsa_controlled150',static function(){
    if(!function_exists('hsa_allowed')||!hsa_allowed())wp_send_json_error('Brak uprawnień.',403);
    check_ajax_referer('hsa','nonce');
    if(($_POST['consent']??'')!=='1')wp_send_json_error('Wymagana zgoda na własny szkic testowy.',400);
    wp_send_json_success(hsa150_run());
});
add_action('wp_ajax_hsa_cleanup150',static function(){
    if(!function_exists('hsa_allowed')||!hsa_allowed())wp_send_json_error('Brak uprawnień.',403);
    check_ajax_referer('hsa','nonce');
    $journal=get_option('hsa150_pending',null);
    if(!$journal)wp_send_json_success(array('confirmed'=>true,'reason'=>'no_pending_fixture'));
    // Avoid deleting a fixture from a request that may still be running.
    if(time()-(int)($journal['started']??0)<600)wp_send_json_error('Odczekaj 10 minut od startu testu.',409);
    try { $result=hsa150_cleanup($journal); }
    catch(Throwable $e) { $result=array('confirmed'=>false,'reason'=>'cleanup_exception'); }
    if($result['confirmed']){
        delete_option('hsa150_pending');
        if(get_option('hsa150_pending',null)!==null)$result=array('confirmed'=>false,'reason'=>'journal_removal_failed');
    }
    wp_send_json_success($result);
});
