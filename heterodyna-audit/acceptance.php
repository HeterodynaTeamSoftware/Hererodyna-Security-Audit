<?php
if (!defined('ABSPATH')) { exit; }
/** Report limitations and acceptance checks without claiming an exploit was verified. */
function hsa_acceptance_summary($s) {
    $files=(int)($s['checked'] ?? 0);
    $skipped=(int)($s['skipped'] ?? 0);
    $total=$files+$skipped;
    $phase=$s['phase'] ?? 'unknown';
    $probes=$s['tests'] ?? array();
    $expected=(int)($s['tests_total'] ?? 0);
    $limits=array();
    if ($skipped>0) $limits[]='Pominięte pliki: '.$skipped;
    if (!empty($s['overflow'])) $limits[]='Osiągnięto limit ustaleń';
    if (!empty($s['model_overflow'])) $limits[]='Osiągnięto limit indeksu plików';
    if (!empty($s['log_overflow'])) $limits[]='Dziennik zdarzeń jest skrócony';
    if ($expected>count($probes)) $limits[]='Nie wykonano wszystkich zaplanowanych prób HTTP';
    if ($phase!=='complete') $limits[]='Skan nie został zakończony';
    return array(
      'version'=>'1.0.0',
      'status'=>$phase==='complete'?'zakończony':'niepełny',
      'files_read'=>$files,'files_skipped'=>$skipped,
      'file_inventory_percent'=>$total ? round(100*$files/$total,1) : null,
      'http_tests_completed'=>count($probes),
      'http_tests_expected'=>$expected,
      'findings_count'=>count($s['findings'] ?? array()),
      'correlations_count'=>count($s['correlations'] ?? array()),
      'limitations'=>$limits,
      'disclaimer'=>'Pokrycie inwentarza nie jest miarą bezpieczeństwa. Wyniki heurystyczne wymagają ręcznej walidacji.'
    );
}
