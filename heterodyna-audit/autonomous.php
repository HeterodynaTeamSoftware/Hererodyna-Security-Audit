<?php
if (!defined('ABSPATH')) exit;
function hsa_autonomy_plan($catalog, $active, $online) {
    $steps=array('inventory','source','permissions','correlation');
    if ($active) $steps[]='anonymous_get';
    if ($online) $steps[]='core_integrity';
    return array('version'=>'1.2.0','mode'=>'read-only','steps'=>$steps,
      'discovery'=>array('plugins'=>count($catalog['plugins'] ?? array()),'themes'=>count($catalog['themes'] ?? array()),'routes'=>count($catalog['routes'] ?? array())),
      'limits'=>array('Bez testów hostingu','Bez metod modyfikujących dane','CVE bez zweryfikowanej bazy pozostają nierozstrzygnięte'));
}
function hsa_autonomy_assess($s) {
    $phase=$s['phase'] ?? 'unknown'; $done=$phase==='complete'; $out=array();
    foreach (($s['autonomy']['steps'] ?? array()) as $id) {
        $status='partial';
        if ($id==='inventory') $status='completed';
        elseif (in_array($id,array('source','permissions','correlation'),true)) $status=$done || $phase==='probes' ? 'completed' : 'partial';
        elseif ($id==='anonymous_get') $status=count($s['tests'] ?? array())===(int)($s['tests_total'] ?? 0) ? 'completed' : 'partial';
        elseif ($id==='core_integrity') $status=($s['integrity'] ?? '')==='Porównanie sum uruchomione' ? 'completed' : 'unresolved';
        $out[]=array('id'=>$id,'status'=>$status);
    }
    $reasons=array('CVE komponentów: brak zweryfikowanej bazy');
    if (!empty($s['skipped'])) $reasons[]='Pominięte pliki: '.(int)$s['skipped'];
    if (!$done) $reasons[]='Skan nie został zakończony';
    return array('steps'=>$out,'unresolved_reasons'=>$reasons,'disclaimer'=>'Ukończenie etapu nie potwierdza bezpieczeństwa.');
}
