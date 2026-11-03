<?php
if (!defined('ABSPATH')) { exit; }
/** Inventory-only, non-invasive classification. Never executes route callbacks. */
function hsa_endpoint_review($catalog) {
    $routes=array();$summary=array('public_declared'=>0,'guard_declared'=>0,'missing_guard'=>0,'mixed'=>0,'unknown'=>0);
    foreach (($catalog['routes'] ?? array()) as $route) {
        $p=$route['permission'] ?? array();
        $hasMissing=in_array('brak callback',$p,true);
        $hasPublic=in_array('jawnie publiczny',$p,true);
        $hasGuard=in_array('callback obecny (niesprawdzony)',$p,true);
        $kinds=(int)$hasMissing+(int)$hasPublic+(int)$hasGuard;
        $state=$kinds>1?'mixed':($hasMissing?'missing_guard':($hasPublic?'public_declared':($hasGuard?'guard_declared':'unknown')));
        $summary[$state]++;
        $methods=array_values(array_filter((array)($route['methods'] ?? array()),'is_string'));
        $routes[]=array('id'=>(string)($route['id'] ?? ''),'path'=>(string)($route['path'] ?? ''),
          'methods'=>$methods,'classification'=>$state,'source_files'=>(array)($route['source_files'] ?? array()),
          'evidence'=>'Metadane rejestracji trasy; nie wykonano callbacku ani testu uprawnień',
          'review'=>$state==='missing_guard'||$state==='mixed');
        if(count($routes)>=1500)break;
    }
    return array('routes'=>$routes,'summary'=>$summary,'ajax'=>array(),
      'limitations'=>array('Nie sprawdzono rzeczywistej autoryzacji wszystkich tras','Publiczny endpoint nie oznacza podatnosci','Nie wykonano POST/PUT/PATCH/DELETE'));
}
/** Reuses the tokenizer findings, rather than generating active requests. */
function hsa_ajax_review($findings) {
    $out=array();
    foreach ((array)$findings as $f) {
        if (($f['rule'] ?? '')!=='PUBLIC_ACTION_REVIEW')continue;
        $out[]=array('file'=>(string)($f['file'] ?? ''),'line'=>(int)($f['line'] ?? 0),
          'registration'=>(string)($f['reason'] ?? ''),'classification'=>'public_registration_review',
          'evidence'=>'Statyczna rejestracja publicznego hooka; brak testu osiagalnosci');
        if(count($out)>=300)break;
    }
    return $out;
}
