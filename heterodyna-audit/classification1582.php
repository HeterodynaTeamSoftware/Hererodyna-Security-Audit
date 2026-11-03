<?php
/**
 * HSA 15.8.2 — evidence-aware classification. Read-only, no site/network operations.
 * Findings from lexical patterns do NOT by themselves constitute security defects.
 */
if (!defined('ABSPATH')) { exit; }

function hsa1582_is_fixture($path) {
    // Intentionally narrow: do not hide vulnerabilities in arbitrary plugins or paths.
    return is_string($path) && (bool)preg_match('~^wp-content/plugins/heterodyna-audit/tests/[^/]+(?:/[^/]+)*$~D', $path);
}

function hsa1582_confirmed_evidence($scan) {
    $confirmed=array();
    foreach ((array)($scan['evidence_ledger']['items']??array()) as $item) {
        if(!is_array($item) || ($item['verdict']??'')!=='confirmed_vulnerability' || empty($item['is_exploit_proven']))continue;
        $target=(string)($item['target']??'');
        // Refuse to paint any result confirmed if the ledger lacks verifiable provenance.
        if ($target!=='' && (string)($item['id']??'')!=='' && (string)($item['evidence']??'')!=='')$confirmed[]=array('target'=>$target,'evidence_id'=>(string)($item['id']??''),
            'kind'=>(string)($item['kind']??''),'proof'=>(string)($item['evidence']??''));
    }
    return $confirmed;
}

function hsa1582_review($scan) {
    $findings=(array)($scan['findings']??array());
    $confirmed=hsa1582_confirmed_evidence($scan);
    $summary=array('version'=>'15.8.2','scope'=>'read_only_report_classification',
        'confirmed_vulnerabilities'=>count($confirmed),'confirmed_records'=>$confirmed,
        'static_signals'=>0,'inventory_or_hardening'=>0,'fixture_excluded'=>0,
        'unproven_critical_alerts_demoted'=>0,'source_mismatch'=>0,
        'static_xss'=>count((array)($scan['xss126_summary']['items']??$scan['xss126']['candidates']??array())),
        'static_csrf'=>count((array)($scan['csrf128_summary']['items']??$scan['csrf128']['items']??array())),
        'file_inventory_only'=>0,'file_paths_to_review'=>0,
        'verification_status'=>($scan['phase']??'')==='complete'?'scan_completed_not_security_certification':'scan_incomplete',
        'coverage_limitations'=>array(), 'excluded_examples'=>array());
    foreach($findings as $item) {
        if(!is_array($item))continue;
        $path=(string)($item['file']??'');
        if(hsa1582_is_fixture($path)){
            $summary['fixture_excluded']++;
            if(count($summary['excluded_examples'])<15)$summary['excluded_examples'][]=$path;
            continue;
        }
        if(($item['priority']??'')==='red')$summary['unproven_critical_alerts_demoted']++;
        $rule=(string)($item['rule']??'');
        if(in_array($rule,array('CONFIG','SKIP','LIMIT','INTEGRITY'),true))$summary['inventory_or_hardening']++;
        else $summary['static_signals']++;
    }
    foreach((array)($scan['file130_summary']['items']??$scan['file130']['items']??array()) as $entry){
        if(!is_array($entry) || hsa1582_is_fixture((string)($entry['file']??'')))continue;
        if(($entry['verdict']??'')==='static_untrusted_path_candidate')$summary['file_paths_to_review']++;
        else $summary['file_inventory_only']++;
    }
    $srcProof=(array)($scan['source_proof158']['counts']??array());
    $summary['source_mismatch']=(int)($srcProof['php_sink_unbound']??0);
    if(!empty($scan['skipped']))$summary['coverage_limitations'][]=(int)$scan['skipped'].' plików pominięto.';
    if(!empty($scan['model_overflow']) || !empty($scan['overflow']))$summary['coverage_limitations'][]='Przekroczono limit indeksowania lub ustaleń.';
    if(($scan['phase']??'')!=='complete')$summary['coverage_limitations'][]='Skan nie został ukończony.';
    $summary['interpretation']='Czerwony status oznacza wyłącznie potwierdzenie naruszenia z dowodem. '
      .'Statyczny sygnał, wykryta instrukcja, dostępny endpoint i wykonany test własnego laboratorium nie są takimi dowodami.';
    return $summary;
}
