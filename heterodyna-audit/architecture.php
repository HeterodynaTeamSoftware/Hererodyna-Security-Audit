<?php
if (!defined('ABSPATH')) { exit; }
// A lexical index, not a resolver of dynamic PHP execution.
function hsa_architecture($source) {
 $ts=token_get_all($source);$out=array('symbols'=>array(),'calls'=>array(),'hooks'=>array(),'includes'=>array(),'guards'=>array(),'inputs'=>array(),'truncated'=>false);$n=count($ts);
 $names=array(T_STRING);foreach(array('T_NAME_QUALIFIED','T_NAME_FULLY_QUALIFIED','T_NAME_RELATIVE') as $c)if(defined($c))$names[]=constant($c);
 for($i=0;$i<$n;$i++) {
  $t=$ts[$i];if(!is_array($t))continue;$id=$t[0];$line=$t[2];
  if(in_array($id,array(T_CLASS,T_INTERFACE,T_TRAIT,T_FUNCTION),true)) {
   $j=$i+1;while($j<$n && (is_array($ts[$j]) && in_array($ts[$j][0],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true) || $ts[$j]==='&'))$j++;
   if($j<$n && is_array($ts[$j]) && $ts[$j][0]===T_STRING)hsa_index_push($out,'symbols',array('name'=>$ts[$j][1],'kind'=>token_name($id),'line'=>$line));
  }
  if($id===T_VARIABLE && in_array($t[1],array('$_GET','$_POST','$_REQUEST','$_COOKIE','$_FILES','$_SERVER'),true))hsa_index_push($out,'inputs',array('name'=>$t[1],'line'=>$line));
  if(in_array($id,array(T_INCLUDE,T_INCLUDE_ONCE,T_REQUIRE,T_REQUIRE_ONCE),true)) {
   $expression='';for($j=$i+1;$j<min($n,$i+30);$j++){if($ts[$j]===';')break;$expression.=is_array($ts[$j])?$ts[$j][1]:$ts[$j];}
   hsa_index_push($out,'includes',array('expression'=>substr(trim($expression),0,240),'line'=>$line,'resolved'=>false));
  }
  if(!in_array($id,$names,true))continue;
  $j=$i+1;while($j<$n && is_array($ts[$j]) && in_array($ts[$j][0],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$j++;
  $p=$i-1;while($p>=0 && is_array($ts[$p]) && in_array($ts[$p][0],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$p--;
  if($j>=$n || $ts[$j]!=='(' || ($p>=0 && is_array($ts[$p]) && $ts[$p][0]===T_FUNCTION))continue;
  $name=ltrim($t[1],'\\');$low=strtolower($name);
  hsa_index_push($out,'calls',array('name'=>$name,'line'=>$line));
  if(in_array($low,array('current_user_can','check_ajax_referer','check_admin_referer','wp_verify_nonce','sanitize_text_field','esc_html','esc_attr','wp_kses','prepare'),true))hsa_index_push($out,'guards',array('name'=>$name,'line'=>$line));
  if(in_array($low,array('add_action','add_filter','do_action','apply_filters','register_rest_route'),true)) {
   $args=array();$depth=0;
   for($k=$j+1;$k<min($n,$j+80);$k++) {
    $v=$ts[$k];if($v===')' && $depth===0)break;
    if($v==='(' || $v==='[')$depth++;if($v===')' || $v===']')$depth--;
    if(is_array($v) && $v[0]===T_CONSTANT_ENCAPSED_STRING && $depth===0)$args[]=substr($v[1],1,-1);
   }
   hsa_index_push($out,'hooks',array('type'=>$name,'literals'=>array_slice($args,0,3),'line'=>$line,'note'=>'Literały argumentów; callback dynamiczny może być nierozwiązany.'));
  }
 }
 return $out;
}
function hsa_index_push(&$out,$key,$value) {if(count($out[$key])<100)$out[$key][]=$value;else $out['truncated']=true;}
function hsa_explanation($rule) {
 $data=array(
 'EVAL'=>array('gray','Kod atakującego musi dotrzeć do eval bez skutecznej kontroli.','Wykonanie PHP z uprawnieniami procesu serwera.'),
 'EVAL_HTTP_INPUT'=>array('yellow','Bezpośrednia obecność danych żądania w eval() wymaga ustalenia osiągalności i braku zabezpieczeń.','Potencjalne wykonanie kodu tylko po potwierdzeniu rzeczywistego wpływu na tekst PHP.'),
 'INCLUDE_INPUT'=>array('yellow','Parametr żądania musi pozwalać wybrać plik poza zamkniętą listą.','Dołączenie nieuprawnionego pliku; w sprzyjających warunkach wykonanie PHP.'),
 'UPLOAD_PHP'=>array('yellow','Plik musi pochodzić od atakującego i być wykonywalny przez serwer WWW.','Uruchomienie kodu na serwerze; sama obecność PHP nie potwierdza infekcji.'),
 'COMMAND'=>array('yellow','Niezaufane dane muszą sterować poleceniem lub argumentami bez skutecznej kontroli.','Wykonanie poleceń systemowych w kontekście procesu PHP.'),
 'DESERIALIZE'=>array('yellow','Atakujący musi kontrolować serializowane dane, ominąć kontrolę podpisu i mieć dostępny użyteczny łańcuch klas.','Manipulacja obiektami; zależnie od klas także zapis plików lub wykonanie kodu.'),
 'WRITE'=>array('yellow','Użytkownik musi kontrolować ścieżkę lub treść zapisu i ominąć autoryzację.','Nadpisanie danych; przy zapisie wykonywalnego PHP możliwe przejęcie strony.'),
 'UPLOAD'=>array('yellow','Przesłany plik musi ominąć kontrole uprawnień, typu i miejsca zapisu.','Zapis niepożądanego pliku; wykonanie kodu zależy od konfiguracji serwera.'),
 'REST'=>array('yellow','Endpoint musi wykonywać operację chronioną bez skutecznej kontroli uprawnień.','Odczyt lub zmiana danych cudzych obiektów. Publiczne trasy mogą być poprawne.'),
 'INTEGRITY'=>array('yellow','Trzeba ustalić, czy zmiana pliku była autoryzowana.','Różnica wobec wydania; nie określa sama w sobie podatności.'),
 'REST_PERMISSION'=>array('yellow','Handler trasy musi wykonywać operację wymagającą autoryzacji bez odpowiednich kontroli.','Możliwy dostęp do nieuprawnionych danych lub operacji; nie dowiedziono. '),
 'REST_EXPOSURE'=>array('yellow','Pozytywny kod HTTP musi faktycznie oznaczać odczyt danych wymagających uprawnień.','Możliwy nieautoryzowany odczyt danych; wymaga ręcznej weryfikacji.'),
 'CONFIG'=>array('yellow','Znaczenie zależy od konfiguracji hostingu i innych uprawnień.','Możliwe ujawnienie informacji lub zwiększenie skutków przejęcia konta.'),
 );
 $r=isset($data[$rule])?$data[$rule]:array('gray','Brak pełnej analizy tego elementu.','Nie określono.');
 return array('priority'=>$r[0],'conditions'=>$r[1],'impact'=>$r[2],'confidence'=>'Heurystyka; wykorzystanie niepotwierdzone');
}
