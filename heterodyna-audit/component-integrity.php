<?php
if (!defined('ABSPATH')) { exit; }
/** Local-only component inventory and integrity posture. CVE matches require a verified advisory feed. */
function hsa_component_posture($catalog) {
    $out = array('components'=>array(), 'advisories'=>array(), 'advisory_status'=>'Nie sprawdzono CVE: brak zweryfikowanego źródła advisory', 'method'=>'Lokalne metadane i manifesty; brak pobierania kodu');
    foreach (array('plugins','themes') as $kind) {
        foreach ((array)($catalog[$kind] ?? array()) as $item) {
            $slug = isset($item['slug']) ? (string)$item['slug'] : '';
            $version = isset($item['version']) ? (string)$item['version'] : '';
            $record = array('id'=>$item['id'], 'name'=>$item['name'], 'type'=>$kind, 'slug'=>$slug, 'version'=>$version, 'active'=>!empty($item['active']), 'integrity'=>'niezweryfikowana', 'cve'=>'niezweryfikowane');
            if ($version === '') { $record['observation']='Brak wersji komponentu; nie można przyporządkować advisory.'; }
            elseif (!preg_match('/^[0-9]+(?:\.[0-9A-Za-z_-]+)*$/D', $version)) { $record['observation']='Niestandardowy numer wersji; automatyczne dopasowanie advisory wymaga ostrożności.'; }
            else { $record['observation']='Zidentyfikowano wersję; bez bazy advisory nie można potwierdzić ani wykluczyć CVE.'; }
            $out['components'][] = $record;
        }
    }
    return $out;
}
