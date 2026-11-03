<?php
/**
 * HSA 15.8.2 — classification of eval() evidence, no execution of scanned PHP.
 * Do not interpret the presence of T_EVAL as RCE. The allowlist is strictly tied
 * to a user-verified local vendor file SHA-256 and exact token locations.
 */
if (!defined('ABSPATH')) { exit; }

function hsa1581_eval_token_at_line($source, $line) {
    foreach (token_get_all($source) as $token) {
        if (is_array($token) && $token[0] === T_EVAL && $token[2] === $line) return true;
    }
    return false;
}

function hsa1581_eval_classify($path, $source, $line) {
    $line = (int) $line;
    $sha = hash('sha256', $source);
    if (!hsa1581_eval_token_at_line($source, $line)) {
        return array('classification'=>'location_mismatch','reportable'=>false,
            'reason'=>'Wskazana linia nie zawiera instrukcji PHP eval().',
            'sha256'=>$sha);
    }
    // Only the precise source proven locally by the site owner's 2026-10-31
    // controlled math test (not a proof of vulnerability or non-vulnerability).
    $known = 'wp-content/plugins/google-site-kit/third-party/phpseclib/phpseclib/phpseclib/Math/BigInteger/Engines/Engine.php';
    $knownHash = 'd662c85eac4e987bd5f11e586511d31dee1c2168f6887c4d6067d16e0443a254';
    if ($path === $known && hash_equals($knownHash, $sha) &&
        in_array($line, array(1060, 1067), true) &&
        strpos($source, 'generateCustomReduction') !== false &&
        strpos($source, 'createRecurringModuloFunction') !== false) {
        return array('classification'=>'verified_expected_library_eval','reportable'=>false,
            'reason'=>'Zgodność dokładnego SHA-256 oraz położenia eval() w wewnętrznym generatorze funkcji phpseclib. Ścieżka 1060 została wykonana na stałych liczbach; nie wykazano sterowania tekstem PHP przez żądanie. Nie oznacza to audytu całej biblioteki.',
            'sha256'=>$sha);
    }
    // A positive evidence of DIRECT HTTP input to eval deserves source review;
    // still NOT a confirmed RCE without reachability and unauthorized effect.
    $lines=preg_split('/\r\n|\n|\r/', $source);
    $near=implode("\n",array_slice($lines,max(0,$line-1),4));
    if (preg_match('/\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i', $near)) {
        return array('classification'=>'direct_http_input_candidate','reportable'=>true,
            'reason'=>'Bezpośrednie dane żądania w wyrażeniu eval(); wymagane ustalenie osiągalności i kontroli dostępu. Sama analiza statyczna nie potwierdza RCE.',
            'sha256'=>$sha);
    }
    return array('classification'=>'unproven_eval_construct','reportable'=>false,
        'reason'=>'Instrukcja PHP eval() jest obecna, ale nie udowodniono wpływu danych użytkownika na tekst wykonywanego kodu. Brak podstaw do alertu o luce.',
        'sha256'=>$sha);
}

function hsa1581_eval_record(&$scan, $path, $source, $line) {
    if (!isset($scan['eval1581'])) {
        $scan['eval1581']=array('verified_expected'=>0,'unproven_not_alerted'=>0,
            'direct_input_to_review'=>0,'location_mismatch'=>0,
            'confirmed_vulnerabilities'=>0,'examples'=>array());
    }
    $result=hsa1581_eval_classify($path,$source,$line);
    $map=array('verified_expected_library_eval'=>'verified_expected',
        'unproven_eval_construct'=>'unproven_not_alerted',
        'direct_http_input_candidate'=>'direct_input_to_review',
        'location_mismatch'=>'location_mismatch');
    $bucket=$map[$result['classification']];$scan['eval1581'][$bucket]++;
    if (count($scan['eval1581']['examples']) < 30 && $bucket!=='unproven_not_alerted') {
        $scan['eval1581']['examples'][]=array('file'=>$path,'line'=>$line,
            'classification'=>$result['classification'],'sha256'=>$result['sha256'],
            'reason'=>$result['reason'],'confirmed_vulnerability'=>false);
    }
    return $result;
}
