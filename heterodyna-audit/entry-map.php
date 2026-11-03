<?php
if (!defined('ABSPATH')) { exit; }
/**
 * v6.2: evidence-based registration map. This reads WordPress's live registrations,
 * never calls third-party callbacks and never sends HTTP requests.
 */
function hsa_map_callable($callback) {
    $out = array('file'=>'', 'line'=>0, 'symbol'=>'', 'status'=>'unresolved');
    try {
        if (is_array($callback) && count($callback) === 2 && is_callable($callback)) {
            $ref = new ReflectionMethod($callback[0], (string)$callback[1]);
        } elseif (is_string($callback) && strpos($callback, '::') !== false && is_callable($callback)) {
            $ref = new ReflectionMethod($callback);
        } elseif ($callback instanceof Closure || (is_string($callback) && function_exists($callback))) {
            $ref = new ReflectionFunction($callback);
        } elseif (is_object($callback) && is_callable($callback)) {
            $ref = new ReflectionMethod($callback, '__invoke');
        } else {
            return $out;
        }
        $name = $ref instanceof ReflectionMethod ? $ref->getDeclaringClass()->getName().'::'.$ref->getName() : $ref->getName();
        $out['symbol'] = substr((string)$name, 0, 180);
        $file = $ref->getFileName();
        $root = realpath(ABSPATH);
        $real = $file ? realpath($file) : false;
        if ($root && $real && strpos($real, rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR) === 0) {
            $out['file'] = str_replace(DIRECTORY_SEPARATOR, '/', substr($real, strlen(rtrim($root, DIRECTORY_SEPARATOR))+1));
            $out['line'] = max(0, (int)$ref->getStartLine());
            $out['status'] = 'mapped';
        } else {
            $out['status'] = 'outside_wordpress_or_internal';
        }
    } catch (Throwable $e) {
        $out['status'] = 'unresolved';
    }
    return $out;
}
function hsa_map_methods($value) {
    $out = array();
    if (is_string($value)) $value = explode(',', $value);
    if (!is_array($value)) return $out;
    foreach ($value as $key=>$v) {
        $candidate = is_string($key) ? $key : $v;
        if (is_string($candidate) && preg_match('/^[A-Za-z]{3,10}$/D', trim($candidate))) {
            $out[strtoupper(trim($candidate))] = true;
        }
    }
    return array_keys($out);
}
function hsa_map_rest_handlers($registered_routes, $limit = 2400) {
    $results = array(); $counts = array('routes'=>0,'handlers'=>0,'mapped'=>0,'unresolved'=>0,'truncated'=>0);
    foreach ((array)$registered_routes as $path=>$handlers) {
        if (!is_string($path) || strlen($path)>500) continue;
        $counts['routes']++;
        // The REST registry includes a separate 'namespace' options entry.
        $items=array();
        foreach ((array)$handlers as $handler) {
            if (!is_array($handler) || !isset($handler['methods'])) continue;
            if ($counts['handlers'] >= $limit) { $counts['truncated']++; continue; }
            $src=hsa_map_callable($handler['callback']??null);
            $guard=hsa_map_callable($handler['permission_callback']??null);
            $has_guard=array_key_exists('permission_callback',$handler) && $handler['permission_callback']!==null;
            $permission= !$has_guard ? 'missing_callback' :
                (is_string($handler['permission_callback']) && $handler['permission_callback']==='__return_true' ? 'declared_public' : 'declared_callback');
            $items[]=array('methods'=>hsa_map_methods($handler['methods']),
                'callback'=>$src, 'permission_callback'=>$guard, 'permission_declaration'=>$permission);
            $counts['handlers']++;
            if($src['status']==='mapped')$counts['mapped']++;else $counts['unresolved']++;
        }
        if ($items) $results[$path]=$items;
    }
    return array('routes'=>$results,'summary'=>$counts);
}
function hsa_map_hook_entries($wp_filter, $limit=1200) {
    $entries=array(); $truncated=0;
    foreach ((array)$wp_filter as $hook=>$registration) {
        if (!is_string($hook) || !preg_match('/^(wp_ajax_(nopriv_)?|admin_post_(nopriv_)?)/',$hook)) continue;
        $callbacks = is_object($registration) && isset($registration->callbacks) ? $registration->callbacks : (is_array($registration) ? $registration : array());
        foreach ((array)$callbacks as $group) {
            foreach ((array)$group as $one) {
                if(!is_array($one) || !array_key_exists('function',$one))continue;
                if(count($entries)>=$limit){$truncated++;continue;}
                $source=hsa_map_callable($one['function']);
                $entries[]=hsa_map_entry('hook',$hook,$source,
                    array('public'=>strpos($hook,'nopriv_')!==false,'registration'=>'runtime_wp_filter'));
            }
        }
    }
    return array('items'=>$entries,'truncated'=>$truncated);
}
function hsa_map_entry($kind,$name,$source,$extra=array()) {
    $key=$kind.'|'.$name.'|'.($source['file']??'').'|'.($source['line']??0).'|'.($source['symbol']??'');
    return array_merge(array('id'=>'@wejscia/'.$kind.'/'.substr(hash('sha256',$key),0,20),
        'kind'=>$kind, 'name'=>substr((string)$name,0,220), 'source'=>$source,
        'tested'=>false,'test_status'=>'inventory_only'),$extra);
}
function hsa_map_component_for_path($file) {
    if (preg_match('~^wp-content/plugins/([^/]+)/~',$file,$m)) return 'plugin:'.$m[1];
    if (preg_match('~^wp-content/plugins/([^/]+\.php)$~',$file,$m)) return 'plugin:'.$m[1];
    if (preg_match('~^wp-content/themes/([^/]+)/~',$file,$m)) return 'theme:'.$m[1];
    if (preg_match('~^wp-content/mu-plugins/([^/]+)~',$file,$m)) return 'must_use:'.$m[1];
    if (preg_match('~^wp-(includes|admin)/~',$file)) return 'core';
    return 'unmapped';
}
function hsa_map_aggregate($routes, $entries) {
    $byFile=array();$byComponent=array(); $routePaths=0;
    $add=function($file,$kind,$identifier) use (&$byFile,&$byComponent) {
        if(!$file)return;
        if(!isset($byFile[$file]))$byFile[$file]=array('rest'=>array(),'hook'=>array(),'shortcode'=>array(),'block'=>array(),'widget'=>array());
        if(!isset($byFile[$file][$kind]))$byFile[$file][$kind]=array();
        if(count($byFile[$file][$kind])<250)$byFile[$file][$kind][$identifier]=true;
        $component=hsa_map_component_for_path($file);
        if(!isset($byComponent[$component]))$byComponent[$component]=array('rest'=>array(),'hook'=>array(),'shortcode'=>array(),'block'=>array(),'widget'=>array());
        if(!isset($byComponent[$component][$kind]))$byComponent[$component][$kind]=array();
        if(count($byComponent[$component][$kind])<500)$byComponent[$component][$kind][$identifier]=true;
    };
    foreach ($routes as $path=>$handlers) {
        $routePaths++;
        foreach($handlers as $handler) {
            foreach (array('callback','permission_callback') as $field) {
                $file=$handler[$field]['file']??'';
                $add($file,'rest',$path);
            }
        }
    }
    foreach ($entries as $entry) $add((string)($entry['source']['file']??''),(string)$entry['kind'],(string)$entry['id']);
    foreach ($byFile as &$k)foreach($k as &$items)$items=array_keys($items);
    unset($k,$items);
    foreach ($byComponent as &$k)foreach($k as &$items)$items=array_keys($items);
    unset($k,$items);
    return array('by_file'=>$byFile,'by_component'=>$byComponent,'registered_rest_paths'=>$routePaths);
}
function hsa_map_discover($catalog) {
    global $wp_filter, $shortcode_tags, $wp_widget_factory;
    $registered=function_exists('rest_get_server') ? rest_get_server()->get_routes() : array();
    $rest=hsa_map_rest_handlers($registered);
    $hooks=hsa_map_hook_entries(isset($wp_filter)?$wp_filter:array());
    $entries=$hooks['items']; $limits=array('hooks'=>$hooks['truncated'],'shortcodes'=>0,'blocks'=>0,'widgets'=>0);
    foreach((array)(isset($shortcode_tags)?$shortcode_tags:array()) as $name=>$callback){
        if(!is_string($name))continue;
        if(count($entries)>=2300){$limits['shortcodes']++;continue;}
        $entries[]=hsa_map_entry('shortcode',$name,hsa_map_callable($callback));
    }
    if(class_exists('WP_Block_Type_Registry') && method_exists('WP_Block_Type_Registry','get_instance')) {
        foreach((array)WP_Block_Type_Registry::get_instance()->get_all_registered() as $name=>$block){
            if(count($entries)>=2300){$limits['blocks']++;continue;}
            $callback=is_object($block) && isset($block->render_callback) ? $block->render_callback : null;
            $entries[]=hsa_map_entry('block',(string)$name,hsa_map_callable($callback),
                array('dynamic'=>is_callable($callback),'registration'=>'runtime_block_registry'));
        }
    }
    if(is_object($wp_widget_factory) && isset($wp_widget_factory->widgets)){
        foreach((array)$wp_widget_factory->widgets as $name=>$widget){
            if(count($entries)>=2300){$limits['widgets']++;continue;}
            $callback=is_object($widget) && method_exists($widget,'widget')?array($widget,'widget'):null;
            $entries[]=hsa_map_entry('widget',is_object($widget) && isset($widget->id_base)?(string)$widget->id_base:(string)$name,hsa_map_callable($callback));
        }
    }
    $aggregate=hsa_map_aggregate($rest['routes'],$entries);
    $kindCount=array('hook'=>0,'shortcode'=>0,'block'=>0,'widget'=>0);
    foreach($entries as $entry)$kindCount[$entry['kind']]++;
    $restWithSources=0;
    foreach($rest['routes'] as $routeHandlers){
        foreach($routeHandlers as $handler){
            if(!empty($handler['callback']['file'])){$restWithSources++;break;}
        }
    }
    $rest['summary']['paths_with_source']=$restWithSources;
    $rest['summary']['files_with_entrypoints']=count($aggregate['by_file']);
    $rest['summary']['components_with_entrypoints']=count($aggregate['by_component']);
    return array('version'=>'6.4.0','rest'=>$rest['routes'],'entries'=>$entries,
        'by_file'=>$aggregate['by_file'],'by_component'=>$aggregate['by_component'],
        'summary'=>array_merge($rest['summary'],$kindCount), 'limits'=>$limits,
        'limitations'=>array('Mapa opiera się na rejestracjach dostępnych podczas żądania administracyjnego.',
           'Plik callbacku oraz jego linia nie dowodzą, że występuje podatność.',
           'Bloki statyczne mogą nie mieć render_callback; brak lokalizacji nie oznacza braku kodu.',
           'Brak aktywnego testu AJAX, shortcode, bloków i widgetów w ZIP 2/12.'));
}
