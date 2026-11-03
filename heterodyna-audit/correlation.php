<?php
if (!defined('ABSPATH')) { exit; }
/** Bounded static co-occurrence, not proof of an exploitable execution path. */
function hsa_correlate($scan) {
 $grouped=array();
 foreach(($scan['findings'] ?? array()) as $f){
  $path=$f['file'] ?? '';
  if(!is_string($path)||!preg_match('~^wp-content/(plugins|themes)/[^/]+/~',$path))continue;
  $grouped[$path][]=$f;
 }
 $results=array();
 foreach($grouped as $path=>$fs){
  $public=array();$risk=array();
  foreach($fs as $f){
   $rule=$f['rule'] ?? '';
   if(in_array($rule,array('PUBLIC_ACTION_REVIEW','REST_PERMISSION'),true))$public[]=$f;
   if(in_array($rule,array('EVAL','INCLUDE_INPUT','COMMAND','DESERIALIZE','WRITE','UPLOAD','PHP_INPUT_OUTPUT','JS_DOM_SINK'),true))$risk[]=$f;
  }
  $count=0;
  foreach($public as $a)foreach($risk as $b){
   if($count++>=12||count($results)>=200)break 2;
   $results[]=array('file'=>$path,'entry_rule'=>$a['rule'],'entry_line'=>(int)($a['line']??0),'operation_rule'=>$b['rule'],'operation_line'=>(int)($b['line']??0),'status'=>'do weryfikacji','confidence'=>'Niska: wspolwystepowanie w pliku, bez dowodu osiagalnosci','recommendation'=>'Sprawdz callback, autoryzacje, nonce, walidacje i przeplyw danych.');
  }
  if(count($results)>=200)break;
 }
 return $results;
}
