<?php
if (!defined('ABSPATH')) { exit; }
/** ZIP 9/12: bounded real, anonymous read-only requests to plugin/theme REST handlers.
 * Never claims that one GET is a complete security test of a plugin, file or handler.
 */
function hsa9_component_from_handler($handler) {
    $file=(string)($handler['callback']['file']??'');
    if (!function_exists('hsa_map_component_for_path')) return '';
    $component=hsa_map_component_for_path($file);
    return (strpos($component,'plugin:')===0 || strpos($component,'theme:')===0) ? $component : '';
}
/** Produce a synthetic high numeric identifier or slug; absence in arbitrary plugin data is not guaranteed. */
function hsa9_fixture_value($name,$pattern) {
    $name=strtolower((string)$name); $pattern=(string)$pattern;
    if(strlen($pattern)>90 || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D',$name)) return null;
    // Names that could trigger remote resource loading or filesystem access are excluded.
    if(preg_match('/(?:url|uri|host|path|file|endpoint|redirect|callback|target|secret|token|nonce|auth|code|command)/',$name)) return null;
    if(strpos($pattern,'.')!==false || strpos($pattern,'|')!==false || strpos($pattern,'(')!==false) return null;
    $numeric=(bool)preg_match('/(?:^id$|_id$|^id_|^page$|^number$|^index$)/',$name);
    $values=$numeric ? array('999999997','0') : array('hsa-probe-9f3c','999999997','0');
    if(!preg_match('~^(?:\\\\?[dwDsS]|[\\[\\]A-Za-z0-9_\\\\+*?{}\-^$])+~D',$pattern)) return null;
    foreach($values as $value) {
        $ok=@preg_match('~^(?:'.str_replace('~','\\~',$pattern).')$~D',$value);
        if($ok===1) return $value;
    }
    return null;
}
function hsa9_materialize_route($route) {
    $route=(string)$route;
    if(strlen($route)>300 || strpos($route,'(?P<')===false || $route==='' || $route[0]!=='/') return array('path'=>null,'reason'=>'unsupported_route_pattern');
    if(preg_match('/\(\?P<([^>]+)>/',$route,$m) && preg_match('/(?:url|uri|host|path|file|token|secret)/i',$m[1])) return array('path'=>null,'reason'=>'unsafe_parameter_name');
    $found=0;$reason='';
    $expanded=preg_replace_callback('~\(\?P<([A-Za-z_][A-Za-z0-9_]*)>([^()]*)\)~',function($m)use(&$found,&$reason){
        $found++;
        $value=hsa9_fixture_value($m[1],$m[2]);
        if($value===null){$reason='no_safe_fixture_for_'.$m[1];return $m[0];}
        return $value;
    },$route);
    if($found===0 || $found>2) return array('path'=>null,'reason'=>'unsupported_group_count');
    if($reason!=='')return array('path'=>null,'reason'=>$reason);
    if(!preg_match('~^/[A-Za-z0-9_./-]+$~D',$expanded) || strpos($expanded,'..')!==false || strpos($expanded,'//')!==false) return array('path'=>null,'reason'=>'nonliteral_or_unsafe_path');
    // Check that the generated path is accepted by the registered WordPress route regex.
    $match=@preg_match('~^'.str_replace('~','\\~',$route).'$~D',$expanded);
    if($match!==1) return array('path'=>null,'reason'=>'fixture_does_not_match_route');
    return array('path'=>$expanded,'reason'=>'');
}
function hsa9_plan($entry_map,$limit=18) {
    $limit=max(0,min(30,(int)$limit));$jobs=array();$skipped=array();$seen=array();$candidates=0;
    foreach((array)($entry_map['rest']??array()) as $route=>$handlers) {
        if(!is_string($route))continue;
        foreach((array)$handlers as $handler) {
            $component=hsa9_component_from_handler($handler);
            if(!$component || !in_array('GET',(array)($handler['methods']??array()),true)) continue;
            if(isset($seen[$route]))continue;
            $seen[$route]=true;
            if(strpos($route,'(?P<')===false)continue; // literal GETs are already covered in v6
            $candidates++;
            $materialized=hsa9_materialize_route($route);
            if($materialized['path']===null) {$skipped[]=array('route'=>$route,'component'=>$component,'reason'=>$materialized['reason']);continue;}
            if(count($jobs)>=$limit) {$skipped[]=array('route'=>$route,'component'=>$component,'reason'=>'component9_limit');continue;}
            $jobs[]=array('id'=>'COMP9-'.substr(hash('sha256',$route.'|'.$materialized['path']),0,16),
                'kind'=>'component_param_get','method'=>'GET','target'=>$materialized['path'],
                'route_pattern'=>$route,'component'=>$component,
                'callback_file'=>$handler['callback']['file']??'','callback_line'=>(int)($handler['callback']['line']??0),
                'expectation'=>'only_observe_anonymous_HTTP_for_synthetic_identifier_not_known_to_exist');
        }
    }
    return array('version'=>'7.6.0','jobs'=>$jobs,'skipped'=>$skipped,'candidates'=>$candidates,
        'limitations'=>array('Tylko anonimowe GET do tras REST z callbackiem przypisanym do wtyczki lub motywu.',
          'Generowane identyfikatory są fikcyjne; HTTP 404 nie testuje istniejących prywatnych obiektów.',
          'Nie wykonuje callbacków AJAX, shortcode ani bloków, metod zmieniających stan ani testów hostingu.',
          'Wynik HTTP 2xx, 401, 403 lub 404 nie potwierdza podatności ani bezpieczeństwa komponentu.'));
}
function hsa9_execute($job) {
    $route=(string)($job['route_pattern']??'');$path=(string)($job['target']??'');
    $fixture=hsa9_materialize_route($route);
    if(!$path || ($fixture['path']??null)!==$path)return array('executed'=>false,'http'=>array('status'=>0,'error'=>'fixture_mismatch'),'verdict'=>'inconclusive','proof'=>'rejected_invalid_fixture');
    $r=hsa_rest_anonymous_http($path);
    $status=(int)($r['status']??0);
    $verdict=empty($r['executed'])?'inconclusive':(in_array($status,array(401,403),true)?'observed_control':'no_security_conclusion');
    $proof=empty($r['executed'])?'http_not_completed':(in_array($status,array(401,403),true)?'anonymous_access_denied_for_synthetic_identifier':'anonymous_response_observed_no_exploit_or_safety_claim');
    return array('executed'=>!empty($r['executed']),'http'=>$r,'verdict'=>$verdict,'proof'=>$proof,
        'explanation'=>'Fikcyjny identyfikator, rzeczywiste anonimowe HTTP GET. Nie sprawdza danych prawdziwego użytkownika ani wszystkich wariantów handlera.');
}
/** Component-level coverage with explicit per-registration scope and observed vs untested counts. */
function hsa9_coverage($catalog,$entry_map,$engine_results,$plan,$enabled=true) {
    $index=array();
    foreach(array('plugins'=>'plugin','themes'=>'theme') as $group=>$type) {
        foreach((array)($catalog[$group]??array()) as $c) {
            $key=$type.':'.($c['slug']??'');
            if(!isset($index[$key]))$index[$key]=array('key'=>$key,'name'=>$c['name']??$key,'type'=>$type,
              'active'=>!empty($c['active']),'registered_rest'=>array(),'registered_non_rest'=>array(),
              'http_cases'=>array(),'http_executed'=>0,'denied'=>0,'public_or_other'=>0,
              'not_tested_rest'=>array(),'claim'=>'Not a security certificate.');
        }
    }
    $tested=array();
    foreach((array)$engine_results as $r) {
        if(!in_array($r['kind']??'',array('rest_get','component_param_get','route86_dynamic_get'),true))continue;
        if(empty($r['executed']))continue;
        $sourceRoute=(in_array($r['kind'],array('component_param_get','route86_dynamic_get'),true))?($r['route_pattern']??''):($r['target']??'');
        $tested[$sourceRoute][]=$r;
    }
    foreach((array)($entry_map['by_component']??array()) as $key=>$groups) {
        if(!isset($index[$key]))continue;
        foreach((array)$groups as $kind=>$items) {
            if($kind==='rest')$index[$key]['registered_rest']=array_values(array_filter(array_unique((array)$items),
                function($route){return strpos((string)$route,'/hsa-lab/v1/')!==0;}));
            else $index[$key]['registered_non_rest'][$kind]=count((array)$items);
        }
    }
    foreach($index as $key=>&$c) {
        foreach($c['registered_rest'] as $route) {
            $matching=(array)($tested[$route]??array());
            if(!$matching) {$c['not_tested_rest'][]=$route;continue;}
            foreach($matching as $r) {
                $c['http_executed']++;
                $code=(int)($r['http']['status']??0);
                if(in_array($code,array(401,403),true))$c['denied']++;else $c['public_or_other']++;
                if(count($c['http_cases'])<70)$c['http_cases'][]=array('id'=>$r['id'],'route'=>$route,
                   'target'=>$r['target'],'http_status'=>$code,'verdict'=>$r['verdict'],
                   'evidence_sha256'=>$r['evidence_sha256']??'');
            }
        }
        $c['rest_count']=count($c['registered_rest']);$c['not_tested_count']=count($c['not_tested_rest']);
    }
    unset($c);
    $http=0;$uncovered=0;foreach($index as $c){$http+=$c['http_executed'];$uncovered+=$c['not_tested_count'];}
    return array('version'=>'7.6.0','enabled'=>(bool)$enabled,'components'=>array_values($index),
        'summary'=>array('components'=>count($index),'planned_new_http'=>count((array)($plan['jobs']??array())),
         'new_skipped'=>count((array)($plan['skipped']??array())),'new_candidate_routes'=>(int)($plan['candidates']??0),
         'attributed_http_cases'=>$http,'uncovered_component_routes'=>$uncovered),
        'limitations'=>'Per-component evidence includes previously executed literal GETs and new synthetic-identifier GETs; AJAX, POST, callbacks and full exploit verification are not performed.');
}
