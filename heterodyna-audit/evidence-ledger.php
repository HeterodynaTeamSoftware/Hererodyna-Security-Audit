<?php
if (!defined('ABSPATH')) { exit; }
/** v4.8: evidence ledger. No new requests or code execution. */
function hsa_evidence_ledger($scan) {
    $items=array(); $counts=array('confirmed_vulnerability'=>0,'observed_control'=>0,'signal'=>0,'inconclusive'=>0);
    $limits=array('items'=>500,'truncated'=>false); $idSeen=array();
    $push=function($item) use (&$items,&$counts,&$limits,&$idSeen) {
        if(count($items)>=$limits['items']) { $limits['truncated']=true;return; }
        $state=$item['verdict'];if(!isset($counts[$state]))$state='inconclusive';
        $item['verdict']=$state;$item['id']='HSA-'.substr(hash('sha256',($item['kind']??'')."\0".($item['target']??'')."\0".($item['parameter']??'')."\0".($item['test']??'')),0,16);
        if(isset($idSeen[$item['id']])) {
            $n=++$idSeen[$item['id']];
            $item['id']='HSA-'.substr(hash('sha256',$item['id']."\0".(string)$n),0,16);
            while(isset($idSeen[$item['id']])){ $item['id']='HSA-'.substr(hash('sha256',$item['id']."\0retry".(string)$n++),0,16); }
            $idSeen[$item['id']]=0;
        } else $idSeen[$item['id']]=0;
        $item['scope']='WordPress CMS';if(!isset($item['is_exploit_proven']))$item['is_exploit_proven']=false;
        $items[]=$item;$counts[$state]++;
    };
    $canary=(array)($scan['private_draft_canary']??array());
    if(!empty($canary['created'])) {
        $exposed=!empty($canary['confirmed_vulnerability']);
        $push(array('kind'=>'private_draft_access','target'=>'wp/v2/posts/{test-draft}','test'=>'Anonymous HTTP disclosure of random private draft marker',
          'verdict'=>$exposed?'confirmed_vulnerability':(in_array($canary['status']??'',array('private_draft_not_exposed'),true)?'observed_control':'inconclusive'),
          'is_exploit_proven'=>$exposed,'evidence'=>(string)($canary['evidence']??''),
          'interpretation'=>$exposed?'Anonimowy klient uzyskał losową treść utworzonego prywatnego szkicu; naruszenie poufności tego obiektu.':'Brak zaobserwowanego dostępu do znacznika w tej próbie.',
          'limitations'=>'Dowód dotyczy jednego wpisu i jednej konfiguracji. Zobacz status usunięcia szkicu.'));
    }
    foreach((array)($scan['rest_behavior_tests']??array()) as $t) {
        $state=(string)($t['status']??'transport_error');
        $verdict=$state==='anonymous_denied'?'observed_control':($state==='anonymous_accepted'?'signal':'inconclusive');
        $push(array('kind'=>'rest_behavior','target'=>(string)($t['path']??''),'test'=>'Anonymous HTTP GET + internal admin reference',
          'verdict'=>$verdict,'evidence'=>'HTTP anonymous '.(int)($t['anonymous']['status']??0).'; administrator '.(int)($t['admin']['status']??0).'; '.(string)($t['anonymous']['error']??''),
          'interpretation'=>(string)($t['interpretation']??''),'limitations'=>(string)($t['coverage']??'')));
    }
    foreach((array)($scan['permission_tests']??array()) as $t) {
        $status=(string)($t['status']??'unresolved');$tested=!empty($t['tested']);
        $verdict=$tested&&$status==='denied'?'observed_control':($tested&&$status==='allowed'?'signal':'inconclusive');
        $push(array('kind'=>'permission_callback','target'=>(string)($t['path']??''),'test'=>'GET permission_callback / anonymous','verdict'=>$verdict,
          'evidence'=>'callback: '.$status.'; '.(string)($t['detail']??''),'interpretation'=>$verdict==='observed_control'?'Odmowa callbacku dla anonimowego kontekstu. Nie potwierdza odmowy przez HTTP ani innych ról.':($verdict==='signal'?'Callback zezwolił anonimowo. To nie jest dowód nieuprawnionego dostępu; trasa może być publiczna.':'Test nie potwierdził skuteczności kontroli.'),
          'limitations'=>'Bez wykonania handlera, bez testów ról i parametrów.'));
    }
    foreach((array)($scan['input_tests']??array()) as $t) {
        $state=(string)($t['status']??'unresolved');
        $verdict=in_array($state,array('sql_error_signal','html_reflection'),true)?'signal':($state==='blocked'?'observed_control':'inconclusive');
        $codes=(array)($t['http_codes']??array());$safeCodes=array();foreach(array('baseline','sql','xss') as $k)$safeCodes[$k]=isset($codes[$k])?(int)$codes[$k]:null;
        $push(array('kind'=>'input_probe','target'=>(string)($t['path']??''),'parameter'=>(string)($t['parameter']??''),'test'=>'3 anonymous GET variants','verdict'=>$verdict,
          'http_codes'=>$safeCodes,'evidence'=>(string)($t['reason']??''),'interpretation'=>$state==='sql_error_signal'?'Różnicowy błąd 5xx nie dowodzi SQL Injection.':($state==='html_reflection'?'Odbicie znacznika HTML nie dowodzi wykonywalnego XSS.':($state==='blocked'?'Odmowa dostępu zaobserwowana dla wariantu testowego.':'Brak potwierdzonej podatności; test nie obejmuje innych wariantów.')),
          'limitations'=>'Bez wykonania JavaScript, bez analizy kontekstu HTML, bez dowodu SQLi.'));
    }
    if(function_exists('hsa66_results')) {
        $comparison=hsa66_results($scan['input66_plan']??array('probes'=>array()),$scan['engine_results']??array());
        foreach($comparison['items'] as $p) {
            $state=$p['result']['status'];
            $verdict=$state==='signal'?'signal':($state==='access_denied'?'observed_control':'inconclusive');
            $push(array('kind'=>'input66_differential','target'=>$p['path'],'parameter'=>$p['parameter'],
                'test'=>'Six real anonymous GET variants (two baselines, SQL probes, inert HTML marker)',
                'verdict'=>$verdict,'evidence'=>(string)$p['probe_id'].'; '.implode(',',(array)($p['result']['signals']??array())).'; HTTP IDs: '.implode(',',(array)$p['case_ids']),
                'interpretation'=>$state==='signal'?'Różnica lub odbicie znacznika. Bez dowodu wykorzystania SQLi/XSS.':'Brak potwierdzenia SQLi/XSS w przetestowanych wariantach.',
                'limitations'=>'Bez wykonania JavaScript lub odczytu SQL; raport nie przechowuje treści odpowiedzi.'));
        }
    }
    foreach((array)($scan['tests']??array()) as $t) {
        $http=(int)($t['status']??0);$verdict=in_array($http,array(401,403),true)?'observed_control':($http>=200&&$http<300?'signal':'inconclusive');
        $push(array('kind'=>'anonymous_http','target'=>(string)($t['description']??''),'test'=>'anonymous GET','verdict'=>$verdict,'http_status'=>$http,
          'evidence'=>'HTTP '.$http,'interpretation'=>$verdict==='observed_control'?'Odmowa dla jednego żądania.':($verdict==='signal'?'Zasób odpowiedział 2xx; publiczny dostęp może być zamierzony.':'Brak rozstrzygającej obserwacji.'),
          'limitations'=>'Nie sprawdzono treści odpowiedzi ani uprawnień innych użytkowników.'));
    }
    $flow=0;foreach((array)($scan['findings']??array()) as $f) {
        $rule=(string)($f['rule']??'');if(!in_array($rule,array('PHP_EVAL_TAINT','PHP_COMMAND_TAINT','PHP_UNSERIALIZE_TAINT','PHP_WRITE_TAINT','PHP_SQL_TAINT','JS_TAINT_TO_HTML'),true))continue;
        $flow++;
        $push(array('kind'=>'static_dataflow','target'=>(string)($f['file']??''),'line'=>(int)($f['line']??0),'test'=>$rule,'verdict'=>'signal',
          'evidence'=>(string)($f['reason']??''),'interpretation'=>'Kandydat z analizy statycznej. Nie potwierdzono osiągalności ani możliwości wykorzystania.',
          'limitations'=>'Uproszczona analiza przepływu, możliwe wyniki fałszywie dodatnie i ujemne.'));
    }
    $total=count((array)($scan['input_specs']??array()));$executed=count((array)($scan['input_tests']??array()));
    $permissionTotal=count((array)($scan['permission_paths']??array()));$permissionExecuted=0;
    foreach((array)($scan['permission_tests']??array()) as $t)if(!empty($t['tested']))$permissionExecuted++;
    return array('version'=>'6.0.0','counts'=>$counts,'items'=>$items,'limits'=>$limits,
      'coverage'=>array('input_probes_planned'=>$total,'input_probes_executed'=>$executed,'permission_callbacks_planned'=>$permissionTotal,'permission_callbacks_executed'=>$permissionExecuted,'static_flow_candidates'=>$flow),
      'policy'=>'confirmed_vulnerability wymaga dokładnego dowodu skutku. Kontrolowany wyciek znacznika szkicu może zostać potwierdzony; 2xx i heurystyki nie są dowodem.',
      'limitations'=>array('Żaden sygnał nie jest automatycznie potwierdzoną podatnością.','Nie testowano wszystkich plików, metod HTTP, ról i parametrów.','Brak testów wykonania payloadów i destrukcyjnych prób.'));
}
