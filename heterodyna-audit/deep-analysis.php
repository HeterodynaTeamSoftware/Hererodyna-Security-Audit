<?php
if (!defined('ABSPATH')) { exit; }
/** Bounded lexical heuristics, never executes inspected source. */
function hsa_deep_analyze($source, $path) {
    if (strlen($source)>2097152) return array();
    $out=array();
    if (preg_match('/\.js$/i',$path)) {
        $rules=array(
          array('JS_DOM_HTML','~\b(?:innerHTML|outerHTML)\s*=~','Przypisanie do HTML DOM','Sprawdź kodowanie danych i użyj textContent dla zwykłego tekstu.'),
          array('JS_DYNAMIC_CODE','~\b(?:eval|Function)\s*\(~','Dynamiczna interpretacja JavaScript','Unikaj interpretacji niezaufanych łańcuchów jako kodu.'),
          array('JS_DOCUMENT_WRITE','~\bdocument\s*\.\s*write\s*\(~','document.write','Sprawdź pochodzenie argumentów i rozważ bezpieczne API DOM.')
        );
        foreach($rules as $r) { if(preg_match_all($r[1],$source,$m,PREG_OFFSET_CAPTURE)) foreach(array_slice($m[0],0,25) as $hit) {
            $out[]=array('rule'=>$r[0],'line'=>substr_count(substr($source,0,$hit[1]),"\n")+1,'reason'=>$r[2].' (heurystyka tekstowa)','fix'=>$r[3]);
        }}
        return array_slice($out,0,80);
    }
    if(!preg_match('/\.(?:php\d*|phtml|inc)$/i',$path)) return array();
    $tokens=token_get_all($source);$count=count($tokens);
    $super=array('$_GET','$_POST','$_REQUEST','$_COOKIE','$_FILES');
    $sinks=array('echo'=>'PHP_OUTPUT_REVIEW','print'=>'PHP_OUTPUT_REVIEW','header'=>'PHP_HEADER_REVIEW','mysqli_query'=>'PHP_SQL_REVIEW','query'=>'PHP_SQL_REVIEW');
    for($i=0;$i<$count;$i++) {
        $t=$tokens[$i];if(!is_array($t))continue;
        $name=strtolower($t[1]);
        if(!isset($sinks[$name]) && !in_array($t[0],array(T_ECHO,T_PRINT),true))continue;
        $rule=isset($sinks[$name])?$sinks[$name]:'PHP_OUTPUT_REVIEW';
        $p=$i-1;while($p>=0 && is_array($tokens[$p]) && in_array($tokens[$p][0],array(T_WHITESPACE,T_COMMENT,T_DOC_COMMENT),true))$p--;
        if($p>=0 && is_array($tokens[$p]) && $tokens[$p][0]===T_FUNCTION)continue;
        $snippet='';$max=min($count,$i+65);
        for($j=$i+1;$j<$max;$j++) {
            $z=$tokens[$j];$v=is_array($z)?$z[1]:$z;
            if($v===';' || $v==='{')break;
            $snippet.=$v;
        }
        $found=false;foreach($super as $s)if(strpos($snippet,$s)!==false){$found=true;break;}
        if(!$found)continue;
        $out[]=array('rule'=>$rule,'line'=>$t[2],
            'reason'=>'Bezpośrednia obecność zmiennej żądania w pobliżu operacji wyjściowej (heurystyka, nie dowód przepływu)',
            'fix'=>'Sprawdź walidację, kontekstowe kodowanie lub parametryzację oraz autoryzację.');
        if(count($out)>=80)break;
    }
    return $out;
}
