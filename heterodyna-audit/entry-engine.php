<?php
if (!defined('ABSPATH')) exit;
/** Inventory-based entrypoint discovery. This is NOT a vulnerability verdict. */
function hsa_entry_engine_discover($catalog) {
    $entries=array(); $limits=array('routes_truncated'=>0,'unmapped'=>0);
    foreach (($catalog['routes'] ?? array()) as $route) {
        if (count($entries)>=1500) { $limits['routes_truncated']++; continue; }
        $path=(string)($route['path'] ?? '');
        if ($path==='' || strlen($path)>500)continue;
        $methods=array_values(array_filter((array)($route['methods'] ?? array()),'is_string'));
        $guards=(array)($route['permission'] ?? array());
        $sources=(array)($route['source_files'] ?? array());
        if (!$sources)$limits['unmapped']++;
        $entry=array('id'=>(string)($route['id'] ?? '@endpointy'.$path),
            'kind'=>'rest','path'=>$path,'methods'=>$methods,'permission'=>$guards,
            'source_files'=>$sources,'namespace'=>(string)($route['namespace'] ?? ''),
            'testable'=>false,'reason'=>'Nie przeprowadzono testu aktywnego. Wymagana kontrola skutków i danych testowych.',
            'status'=>'not_tested');
        $entries[]=$entry;
    }
    return array('version'=>'4.2.0','entries'=>$entries,'limits'=>$limits,
       'scope'=>'Wyłącznie WordPress CMS; brak skanowania hostingu',
       'policy'=>'Brak automatycznych żądań do nieznanych tras; niektóre GET mogą modyfikować dane.');
}
function hsa_entry_engine_results($scan) {
    $tests=array();
    foreach ((array)($scan['tests'] ?? array()) as $test) {
        $status=(int)($test['status'] ?? 0);
        $state=(string)($test['state'] ?? 'inconclusive');
        $result='inconclusive';
        if ($state==='blocked')$result='control_observed';
        elseif ($state==='public')$result='public_expected';
        elseif ($state==='review')$result='access_observed_requires_context';
        elseif ($state==='not_applicable')$result='not_applicable';
        $tests[]=array('path'=>(string)($test['path'] ?? ''),'method'=>'GET',
          'result'=>$result,'http_status'=>$status,
          'evidence'=>'Zaobserwowano HTTP '.$status.' dla konkretnego anonimowego żądania',
          'limitations'=>'Nie potwierdza odporności innych metod, ról i parametrów.');
    }
    return $tests;
}
function hsa_entry_engine_metrics($results) {
    $metrics=array('executed'=>0,'control_observed'=>0,'public_expected'=>0,'requires_context'=>0,'inconclusive'=>0);
    foreach ($results as $test) {
        $metrics['executed']++;
        $status=$test['result'] ?? 'inconclusive';
        if ($status==='control_observed')$metrics['control_observed']++;
        elseif ($status==='public_expected')$metrics['public_expected']++;
        elseif ($status==='access_observed_requires_context')$metrics['requires_context']++;
        else $metrics['inconclusive']++;
    }
    return $metrics;
}
