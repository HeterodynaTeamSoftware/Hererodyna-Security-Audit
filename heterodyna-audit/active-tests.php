<?php
if (!defined('ABSPATH')) { exit; }
/** Only these known, non-mutating core GET paths may be probed. */
function hsa_probe_specs() {
    return array(
        array('id'=>'settings','path'=>'wp/v2/settings','expect'=>'private','description'=>'Ustawienia administracyjne'),
        array('id'=>'plugins','path'=>'wp/v2/plugins','expect'=>'private','description'=>'Lista zainstalowanych wtyczek'),
        array('id'=>'themes','path'=>'wp/v2/themes','expect'=>'private','description'=>'Lista zainstalowanych motywów'),
        array('id'=>'drafts','path'=>'wp/v2/posts','query'=>array('status'=>'draft','per_page'=>1),'expect'=>'private_ambiguous','description'=>'Odczyt szkiców wpisów'),
        array('id'=>'users','path'=>'wp/v2/users','query'=>array('per_page'=>1),'expect'=>'public','description'=>'Publiczne profile autorów (zwykle dostępne)'),
    );
}
function hsa_classify_probe($spec, $status) {
    if ($status === 0) { return array('state'=>'inconclusive','priority'=>'gray','message'=>'Brak odpowiedzi HTTP — próba nierozstrzygnięta.'); }
    if ($status === 401 || $status === 403) { return array('state'=>'blocked','priority'=>'gray','message'=>'Dostęp anonimowy odrzucony (HTTP '.$status.').'); }
    if ($status >= 200 && $status < 300) {
        if ($spec['expect'] === 'public') { return array('state'=>'public','priority'=>'gray','message'=>'Dostęp publiczny może być zamierzony; brak dowodu luki.'); }
        return array('state'=>'review','priority'=>$spec['expect']==='private' ? 'red' : 'yellow','message'=>'Anonimowe żądanie otrzymało HTTP '.$status.'. Sprawdź treść i reguły dostępu; nie przesądzamy o wycieku.');
    }
    if ($status === 404 || $status === 405) { return array('state'=>'not_applicable','priority'=>'gray','message'=>'Trasa nieobsługiwana (HTTP '.$status.').'); }
    return array('state'=>'inconclusive','priority'=>'gray','message'=>'HTTP '.$status.' nie rozstrzyga poprawności autoryzacji.');
}
function hsa_run_probe($spec) {
    // The caller cannot supply any path, hostname, method or body to this function.
    $home = wp_parse_url(home_url('/'));
    $url = rest_url($spec['path']);
    if (!empty($spec['query'])) { $url = add_query_arg($spec['query'], $url); }
    $target = wp_parse_url($url);
    $valid = is_array($home) && is_array($target)
        && isset($home['host'], $home['scheme'], $target['host'], $target['scheme'])
        && strtolower($home['host']) === strtolower($target['host'])
        && strtolower($home['scheme']) === strtolower($target['scheme'])
        && (isset($home['port']) ? (int)$home['port'] : null) === (isset($target['port']) ? (int)$target['port'] : null)
        && in_array(strtolower($target['scheme']), array('https','http'), true)
        && !isset($target['user']) && !isset($target['pass']);
    if (!$valid) {
        return array('id'=>$spec['id'],'path'=>$spec['path'],'description'=>$spec['description'],
            'status'=>0,'state'=>'inconclusive','priority'=>'gray','milliseconds'=>0,
            'message'=>'Adres REST ma inny origin niż home_url; test pominięty.');
    }
    $started = microtime(true);
    $r = wp_safe_remote_get($url, array('timeout'=>5,'redirection'=>0,'limit_response_size'=>4096,
        'cookies'=>array(),'headers'=>array('Accept'=>'application/json','User-Agent'=>'HeterodynaAudit/0.3.0 (authorized site audit)'),
        'sslverify'=>true));
    $elapsed = (int) round(1000*(microtime(true)-$started));
    if (is_wp_error($r)) {
        return array('id'=>$spec['id'],'path'=>$spec['path'],'description'=>$spec['description'],
            'status'=>0,'state'=>'inconclusive','priority'=>'gray','milliseconds'=>$elapsed,
            'message'=>'Żądanie nieudane: '.$r->get_error_code().'. Brak możliwości potwierdzenia dostępu.');
    }
    $status = (int) wp_remote_retrieve_response_code($r);
    $classification = hsa_classify_probe($spec, $status);
    return array_merge(array('id'=>$spec['id'],'path'=>$spec['path'],'description'=>$spec['description'],
        'status'=>$status,'milliseconds'=>$elapsed),$classification);
}
