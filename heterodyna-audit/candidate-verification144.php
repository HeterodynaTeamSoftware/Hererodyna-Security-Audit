<?php
if (!defined('ABSPATH')) { exit; }
/**
 * Heterodyna v14.4 / Stage VII 2/3: correlate actual permission-gate evidence
 * with existing static candidate-to-entrypoint links. No endpoint is invoked.
 * A gate denial is NOT a proof that the sink is safe; a gate pass is NOT an exploit.
 */
function hsa144_candidate_digest_valid($candidate) {
    if(!is_array($candidate) || !is_string($candidate['file']??null) ||
        !is_string($candidate['family']??null) ||
        !is_int($candidate['line']??null) && !ctype_digit((string)($candidate['line']??'')) ||
        !preg_match('/^[a-f0-9]{64}$/D',(string)($candidate['source_sha256']??''))) return false;
    $recomputed=hash('sha256',json_encode(array('hsa134/v1',$candidate['file'],
        $candidate['family'],(int)$candidate['line'],$candidate['source_sha256'],
        (array)($candidate['links']??array())),JSON_UNESCAPED_SLASHES));
    return preg_match('/^[a-f0-9]{64}$/D',(string)($candidate['evidence_sha256']??''))===1 &&
        hash_equals($recomputed,(string)$candidate['evidence_sha256']);
}
/** Returns validated permission-only evidence by exact REST method, route, mapped callback and line. */
function hsa144_gate_index($scan) {
    $jobs=array();$duplicate=array();$records=array();$duplicateRecords=array();
    foreach((array)($scan['engine_plan']['jobs']??array()) as $job){
        if(!in_array(($job['kind']??''),array('guard136_boundary','write138_gate'),true))continue;
        $id=(string)($job['id']??'');if($id==='')continue;
        if(isset($jobs[$id]))$duplicate[$id]=true;
        else $jobs[$id]=$job;
    }
    foreach((array)($scan['engine_results']??array()) as $record){
        if(!in_array(($record['kind']??''),array('guard136_boundary','write138_gate'),true))continue;
        $id=(string)($record['id']??'');if($id==='')continue;
        if(isset($records[$id]))$duplicateRecords[$id]=true;
        else $records[$id]=$record;
    }
    $index=array();
    foreach($jobs as $id=>$job){
        $method=($job['kind']??'')==='guard136_boundary'?'GET':strtoupper((string)($job['method']??''));
        $key=implode('|',array($method,(string)($job['target']??''),
          (string)($job['callback_file']??''),(int)($job['callback_line']??0)));
        $state='missing_result';$verdict='not_observed';$sha='';$roles=array();
        if(isset($duplicate[$id]) || isset($duplicateRecords[$id]))$state='duplicate_evidence';
        elseif(isset($records[$id])) {
            $record=$records[$id];
            $v=function_exists('hsa140_gate_record')?hsa140_gate_record($job,$record):array('valid'=>false);
            if(empty($v['valid']))$state='invalid_evidence';
            elseif(!empty($v['diagnostic']))$state='request_diagnostic_no_gate';
            else $state='verified_permission_gate_only';
            $verdict=(string)($record['verdict']??'');
            $sha=(string)($record['evidence_sha256']??'');
            if($state==='verified_permission_gate_only')$roles=array(
                'anonymous'=>(string)($v['anon']??''),'subscriber'=>(string)($v['subscriber']??''));
        }
        $index[$key][]=array('id'=>$id,'state'=>$state,'verdict'=>$verdict,
            'evidence_sha256'=>$sha,'roles'=>$roles,'handler_executed'=>false);
    }
    return $index;
}
function hsa144_link_methods($methods) {
    if(!is_string($methods))return array();
    $out=array();foreach(explode(',',$methods) as $item){
        $item=strtoupper(trim($item));
        if(in_array($item,array('GET','POST','PUT','PATCH','DELETE'),true))$out[$item]=true;
    }
    return array_keys($out);
}
/** Pure read-only triage of already recorded evidence. */
function hsa144_assess($scan,$limit=120) {
    $limit=max(0,min(250,(int)$limit));
    $candidates=(array)($scan['stage6_reachability134']['items']??array());
    $index=hsa144_gate_index($scan);
    $counts=array('static_candidates'=>count($candidates),'static_digest_invalid'=>0,
        'direct_registration_candidates'=>0,'one_hop_candidates'=>0,
        'gate_verified_links'=>0,'gate_denials_observed'=>0,'gate_passes_observed'=>0,
        'request_diagnostic_links'=>0,'invalid_gate_links'=>0,
        'rest_links_without_gate'=>0,'hook_links_not_executed'=>0,
        'unlinked_or_unresolved'=>0,'confirmed_exploits'=>0,'actual_third_party_handler_calls'=>0);
    $rows=array();
    foreach($candidates as $candidate){
        if(!hsa144_candidate_digest_valid($candidate)){$counts['static_digest_invalid']++;continue;}
        $links=(array)($candidate['links']??array());$resolved=array();$statuses=array();
        foreach($links as $link) {
            if(!is_array($link))continue;
            $type=(string)($link['type']??'');$kind=(string)($link['kind']??'');
            if($kind==='static_direct_registration')$counts['direct_registration_candidates']++;
            elseif($kind==='static_one_hop_same_file')$counts['one_hop_candidates']++;
            if($type!=='rest') {
                $counts['hook_links_not_executed']++;
                $resolved[]=array('type'=>'hook','entry'=>$link['entry']??'','method'=>'HOOK',
                    'status'=>'hook_not_actively_verified','evidence_id'=>'');
                $statuses[]='hook_not_actively_verified';continue;
            }
            foreach(hsa144_link_methods((string)($link['methods']??'')) as $method) {
                $key=implode('|',array($method,(string)($link['entry']??''),
                    (string)($candidate['file']??''),(int)($link['callback_line']??0)));
                $matches=$index[$key]??array();
                $gate=count($matches)===1?$matches[0]:null;
                $status=$gate?$gate['state']:'rest_without_exact_gate_evidence';
                if(count($matches)>1)$status='ambiguous_gate_evidence';
                if($status==='verified_permission_gate_only'){
                    $counts['gate_verified_links']++;
                    foreach((array)$gate['roles'] as $role=>$observed) {
                        if(strpos($observed,'denied_')===0)$counts['gate_denials_observed']++;
                        elseif(strpos($observed,'passed_handler_suppressed')!==false)$counts['gate_passes_observed']++;
                    }
                } elseif($status==='request_diagnostic_no_gate')$counts['request_diagnostic_links']++;
                elseif(in_array($status,array('invalid_evidence','duplicate_evidence','ambiguous_gate_evidence'),true))$counts['invalid_gate_links']++;
                else $counts['rest_links_without_gate']++;
                $resolved[]=array('type'=>'rest','entry'=>$link['entry']??'','method'=>$method,
                    'status'=>$status,'evidence_id'=>$gate['id']??'',
                    'evidence_sha256'=>$gate['evidence_sha256']??'',
                    'anonymous'=>$gate['roles']['anonymous']??'not_verified',
                    'subscriber'=>$gate['roles']['subscriber']??'not_verified',
                    'handler_executed'=>false);
                $statuses[]=$status;
            }
        }
        if(!$resolved)$counts['unlinked_or_unresolved']++;
        $state=in_array('verified_permission_gate_only',$statuses,true)?'gate_observed_handler_not_executed':
            (in_array('request_diagnostic_no_gate',$statuses,true)?'request_diagnostic_only':
             (in_array('invalid_evidence',$statuses,true)||in_array('duplicate_evidence',$statuses,true)?
                'evidence_requires_review':($resolved?'static_link_without_runtime_confirmation':'no_entrypoint_link')));
        $row=array('family'=>$candidate['family'],'file'=>$candidate['file'],
            'line'=>(int)$candidate['line'],'operation'=>$candidate['operation']??'',
            'source_sha256'=>$candidate['source_sha256'],'candidate_sha256'=>$candidate['evidence_sha256'],
            'status'=>$state,'entries'=>$resolved,'confirmed_vulnerability'=>false,
            'handler_executed'=>false,'recommendation'=>($state==='gate_observed_handler_not_executed'
               ?'Gate decision only; validate impact with a separately approved reversible fixture.'
               :'No proven execution or unauthorized effect. Follow up with a safe fixture contract.'));
        $row['triage_sha256']=hash('sha256',json_encode(array('hsa144/v1',$row['file'],$row['line'],
            $row['candidate_sha256'],$row['entries'],$row['status']),JSON_UNESCAPED_SLASHES));
        if(count($rows)<$limit)$rows[]=$row;
    }
    return array('version'=>'15.4.0','status'=>$counts['static_digest_invalid']>0?
            'partial_evidence_integrity_failure':'bounded_candidate_gate_triage',
        'stats'=>$counts,'rows'=>$rows,'truncated'=>count($candidates)>count($rows),
        'confirmed_vulnerabilities'=>0,'external_http'=>0,'third_party_handlers_executed'=>0,
        'limitations'=>array(
           'A real REST permission gate was dispatched, but the actual endpoint handler was intentionally suppressed.',
           'A denial can also come from an earlier WordPress filter. A pass is not evidence of an unauthorized write.',
           'Static callback links are restricted to direct or one-hop same-file code matching.',
           'No live PHP sink, SQL query, JavaScript, file operation or third-party write handler executed by this module.',
           'Hashes are self-reported integrity checks, not signed evidence of exploitation.'));
}
