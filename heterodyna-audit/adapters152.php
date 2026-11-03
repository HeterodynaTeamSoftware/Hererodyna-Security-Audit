<?php
if (!defined('ABSPATH')) { exit; }
/** Allowlisted adapters: standard REST posts controller, title update, owned draft only. */
function hsa152_callback_is($callback,$controller,$method) {
    return is_array($callback)&&count($callback)===2&&$callback[0]===$controller&&$callback[1]===$method;
}
function hsa152_route_handler($routes,$path) {
    foreach($routes as $pattern=>$handlers){
        if(@preg_match('@^'.$pattern.'$@i',$path)!==1)continue;
        foreach($handlers as $handler){
            if(is_array($handler)&&!empty($handler['methods']['POST']))return $handler;
        }
    }
    return null;
}
function hsa152_catalog($private=false) {
    $out=array();
    if(!function_exists('get_post_types')||!function_exists('rest_get_server'))return $out;
    $routes=rest_get_server()->get_routes();
    foreach(get_post_types(array('show_in_rest'=>true),'objects') as $type){
        $name=(string)$type->name;
        $item=array('id'=>'title:'.$name,'post_type'=>$name,'supported'=>false,'reason'=>'unsupported_controller');
        $controller=method_exists($type,'get_rest_controller')?$type->get_rest_controller():null;
        if(!is_object($controller)||get_class($controller)!=='WP_REST_Posts_Controller'){$out[]=$item;continue;}
        if(!in_array($name,array('post','page'),true)&&!empty($type->_builtin)){$item['reason']='internal_type';$out[]=$item;continue;}
        if(!post_type_supports($name,'title')){$item['reason']='title_not_supported';$out[]=$item;continue;}
        $base=!empty($type->rest_base)?$type->rest_base:$name;
        $ns=!empty($type->rest_namespace)?$type->rest_namespace:'wp/v2';
        if(!preg_match('~^[a-zA-Z0-9_-]+$~D',$base)||!preg_match('~^[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$~D',$ns)){
            $item['reason']='unsupported_route_shape';$out[]=$item;continue;
        }
        $path='/'.$ns.'/'.$base;
        $handler=hsa152_route_handler($routes,$path.'/2147483001');
        $permission=$handler['permission_callback']??null;
        if(!$handler||!hsa152_callback_is($handler['callback']??null,$controller,'update_item')){
            $item['reason']='handler_replaced_or_missing';$out[]=$item;continue;
        }
        $permissionKind=hsa152_callback_is($permission,$controller,'update_item_permissions_check')?'core_permission':
            ($permission==='__return_true'?'explicit_public':'unsupported');
        if($permissionKind==='unsupported'){$item['reason']='custom_permission_requires_adapter';$out[]=$item;continue;}
        $cap=$type->cap->edit_posts??'';
        if(!$cap||!current_user_can($cap)){$item['reason']='operator_missing_capability';$out[]=$item;continue;}
        $ref=new ReflectionMethod($controller,'update_item');$file=$ref->getFileName();
        $hash=$file&&is_readable($file)?hash_file('sha256',$file):false;
        if(!$hash){$item['reason']='callback_source_unavailable';$out[]=$item;continue;}
        $item=array_merge($item,array('supported'=>true,'reason'=>'ready','route_base'=>$path,'edit_cap'=>$cap,
            'handler'=>'WP_REST_Posts_Controller::update_item','permission'=>$permissionKind,
            'source_sha256'=>$hash,'source_line'=>$ref->getStartLine(),
            'source_file'=>strpos(str_replace('\\','/',$file),rtrim(str_replace('\\','/',ABSPATH),'/').'/')===0?substr(str_replace('\\','/',$file),strlen(rtrim(str_replace('\\','/',ABSPATH),'/'))+1):'[outside_wordpress_root]',
            'operation'=>'POST title; owned draft; anonymous and authorized control',
            'scope'=>in_array($name,array('post','page'),true)?'core_content_type':'custom_content_type_core_controller'));
        $item['binding_sha256']=hash('sha256',json_encode($item));
        if($private){$item['_controller']=$controller;$item['_permission']=$permission;}
        $out[]=$item;
    }
    return $out;
}
function hsa152_run($id,$binding) {
    if(!current_user_can('manage_options'))return array('status'=>'forbidden');
    $selected=null;
    foreach(hsa152_catalog(true) as $item)if($item['id']===$id){$selected=$item;break;}
    if(!$selected||empty($selected['supported']))return array('status'=>'unsupported_adapter','adapter_id'=>$id);
    if(!is_string($binding)||!hash_equals($selected['binding_sha256'],$binding))return array('status'=>'stale_adapter_refresh_required');
    $controller=$selected['_controller'];$permission=$selected['_permission'];
    unset($selected['_controller'],$selected['_permission']);
    $observed=array();
    $dispatch=static function($request)use($controller,$permission,&$observed){
        $seen=false;$matched=false;$writeFromHandler=false;
        $observer=static function($response,$handler,$actual)use($request,$controller,$permission,&$seen,&$matched){
            if($actual!==$request)return $response;
            $seen=true;
            $matched=hsa152_callback_is($handler['callback']??null,$controller,'update_item')&&
                ($handler['permission_callback']??null)===$permission;
            return $matched?$response:new WP_Error('hsa152_handler_changed','Adapter handler changed.',array('status'=>409));
        };
        // Verify the write event came from this controller's update_item stack,
        // not just from a pre-dispatch filter returning a convenient status.
        $writeObserver=static function($postId,$after,$before)use($request,$controller,&$writeFromHandler){
            if((int)$postId!==(int)basename($request->get_route())||
                $after->post_title!==$request->get_param('title')||$before->post_title===$after->post_title)return;
            foreach(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS|DEBUG_BACKTRACE_PROVIDE_OBJECT,40) as $frame){
                if(($frame['object']??null)===$controller&&($frame['function']??'')==='update_item'){
                    $writeFromHandler=true;break;
                }
            }
        };
        add_action('post_updated',$writeObserver,PHP_INT_MAX,3);
        add_filter('rest_request_before_callbacks',$observer,PHP_INT_MAX,3);
        try{return rest_do_request($request);}
        finally{
            remove_filter('rest_request_before_callbacks',$observer,PHP_INT_MAX);
            remove_action('post_updated',$writeObserver,PHP_INT_MAX);
            $observed[]=array('handler_observed'=>$seen,'binding_matched'=>$matched,'write_from_bound_handler'=>$writeFromHandler);
        }
    };
    $result=hsa150_run(array('post_type'=>$selected['post_type'],'route_base'=>$selected['route_base'],
        'edit_cap'=>$selected['edit_cap'],'dispatch'=>$dispatch));
    $result['adapter']=$selected;$result['dispatch_evidence']=$observed;
    $result['source_binding_rechecked']=false;
    foreach(hsa152_catalog() as $now)if($now['id']===$id&&isset($now['binding_sha256']))
        $result['source_binding_rechecked']=hash_equals($binding,$now['binding_sha256']);
    $bound=count($observed)===2&&$result['source_binding_rechecked'];
    foreach($observed as $attempt)$bound=$bound&&$attempt['handler_observed']&&$attempt['binding_matched'];
    if(!empty($result['anonymous']['marker_written']))$bound=$bound&&!empty($observed[0]['write_from_bound_handler']);
    if(!empty($result['authorized']['marker_written']))$bound=$bound&&!empty($observed[1]['write_from_bound_handler']);
    $result['handler_attribution_confirmed']=$bound;
    if(!$bound&&in_array($result['status'],array('tested_boundary_held','unauthorized_fixture_write_observed'),true)){
        $result['unattributed_status']=$result['status'];$result['status']='inconclusive_handler_attribution';
    }
    $result['scope']='selected_title_adapter_only';
    $result['third_party_findings_confirmed']=0;
    $result['release']='15.4.0';
    if(function_exists('hsa154_receipt'))$result=hsa154_receipt($result);
    update_option('hsa150_last_result',$result,false);
    $history=get_option('hsa152_results',array());
    if(!is_array($history))$history=array();
    $history[$id]=$result;
    update_option('hsa152_results',array_slice($history,-30,null,true),false);
    return $result;
}
add_action('wp_ajax_hsa_adapters152',static function(){
    if(!hsa_allowed())wp_send_json_error('Brak uprawnień.',403);
    check_ajax_referer('hsa','nonce');
    wp_send_json_success(array('catalog'=>hsa152_catalog(),'results'=>get_option('hsa152_results',array())));
});
add_action('wp_ajax_hsa_adapter_run152',static function(){
    if(!hsa_allowed())wp_send_json_error('Brak uprawnień.',403);
    check_ajax_referer('hsa','nonce');
    if(($_POST['consent']??'')!=='1')wp_send_json_error('Wymagana zgoda na własny szkic.',400);
    $id=$_POST['adapter_id']??null;$binding=$_POST['binding']??null;
    if(!is_string($id)||!preg_match('/^title:[a-z0-9_-]{1,20}$/D',$id)||!is_string($binding)||!preg_match('/^[a-f0-9]{64}$/D',$binding))
        wp_send_json_error('Nieprawidłowy adapter.',400);
    wp_send_json_success(hsa152_run($id,$binding));
});
