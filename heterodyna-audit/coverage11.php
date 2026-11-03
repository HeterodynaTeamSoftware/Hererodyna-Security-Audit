<?php
if (!defined('ABSPATH')) { exit; }
/**
 * 11/12: Inventory coverage and safe correlation of performed HTTP cases with
 * registered REST handlers. No callback is invoked by this module.
 */
function hsa11_coverage($s) {
    $checked = max(0,(int)($s['checked']??0));
    $indexed = count((array)($s['files']??array()));
    $skipped = max(0,(int)($s['skipped']??0));
    $over = max(0,(int)($s['model_overflow']??0));
    $missing = max(0,$checked - $indexed);
    return array(
        'checked'=>$checked, 'indexed'=>$indexed, 'skipped'=>$skipped,
        'missing_index'=>$missing, 'index_limit'=>(int)($s['file_index_limit']??10000),
        'over_limit'=>$over, 'complete'=> $missing===0 && $over===0,
        'all_files_security_tested'=>false,
        'limits'=>array('readable_files_only'=>true, 'size_max_bytes'=>2097152,
            'meaning'=>'Completeness of readable-file metadata only; not dynamic attack coverage'),
        'frontend'=>array('forms_found'=>(int)($s['frontend8']['forms_found']??0),
            'forms_stored'=>(int)($s['frontend8']['forms_stored']??0),
            'forms_per_file_limit'=>(int)($s['frontend8']['limits']['forms_per_file']??6))
    );
}
function hsa11_file_evidence($s) {
    $byFile = array();
    $byRoute = array();
    foreach ((array)($s['engine_results']??array()) as $r) {
        if (!is_array($r) || empty($r['executed'])) continue;
        $route = (string)($r['route_pattern'] ?? ($r['target']??''));
        if ($route==='' || $route[0]!=='/') continue;
        $byRoute[$route][] = $r;
    }
    $filesWithHttp=0; $routesWithHttp=0;
    foreach ((array)($s['entry_map']['by_file']??array()) as $file=>$registered) {
        if (!is_string($file) || !isset($s['files'][$file])) continue;
        $routes=array_values(array_unique((array)($registered['rest']??array())));
        if (!$routes) continue;
        $found=0; $records=array();
        foreach ($routes as $route) {
            $cases=(array)($byRoute[$route]??array());
            if (!$cases) continue;
            $found++; $routesWithHttp++;
            foreach($cases as $r) {
                if (count($records)>=60) break;
                $records[]=array('id'=>(string)($r['id']??''), 'route'=>$route,
                   'status'=>(int)($r['http']['status']??0),
                   'verdict'=>(string)($r['verdict']??'inconclusive'),
                   'callback_verified'=>!empty($r['callback_verified']),
                   'sha256'=>(string)($r['evidence_sha256']??''));
            }
        }
        if ($found) $filesWithHttp++;
        $byFile[$file]=array('registered_routes'=>count($routes), 'tested_routes'=>$found,
            'untested_routes'=>count($routes)-$found, 'records'=>$records,
            'records_capped'=>count($records)>=60,
            'limitation'=>'Correlation by registered handler file, not proof of reachable vulnerable code');
    }
    return array('summary'=>array('registered_files'=>count($byFile),
        'files_with_http'=>$filesWithHttp, 'route_file_links_with_http'=>$routesWithHttp),
        'by_file'=>$byFile);
}
