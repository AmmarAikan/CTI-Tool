import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type DarkWebResult, type ExternalJob } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n } from '../i18n/I18nContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';

const PAGE_SIZE = 25;
function Highlight({text,keyword}:{text:string;keyword:string}){const at=text.toLocaleLowerCase().indexOf(keyword.toLocaleLowerCase());return at<0?<>{text}</>:<>{text.slice(0,at)}<mark>{text.slice(at,at+keyword.length)}</mark>{text.slice(at+keyword.length)}</>}
function Result({item,keyword}:{item:DarkWebResult;keyword:string}){const {t,dateTime}=useI18n();return <article className="dark-result"><span>{t(item.status==='new'?'newResult':'knownResult')}</span><small>{item.onion_reference} · {item.provider}</small><h3>{item.title}</h3><p><Highlight text={item.excerpt} keyword={keyword}/></p><small>{dateTime(item.first_seen_at)} · {t(item.privacy_status==='reviewed'?'privacyReviewed':'privacyReviewRequired')}</small></article>}
function safeActionError(error:unknown,t:ReturnType<typeof useI18n>['t']){if(error instanceof ApiError&&error.status===401)return t('sessionExpired');if(error instanceof ApiError&&error.status===403)return t('forbidden');if(error instanceof ApiError&&error.status===409)return t('duplicateWatch');if(error instanceof ApiError&&error.status===422)return t('invalidWatchKeyword');if(error instanceof ApiError&&error.status===503)return t('darkWebUnavailable');if(error instanceof ApiError&&error.code==='invalid_response')return t('malformed');if(error instanceof TypeError)return t('disconnected');return t('watchSaveFailed')}

export function DarkWebWatches(){
  const {can}=useAuth(),{t,number,dateTime}=useI18n();
  const [keyword,setKeyword]=useState(''),[selected,setSelected]=useState(''),[offset,setOffset]=useState(0),[job,setJob]=useState<ExternalJob>(),[jobWatchId,setJobWatchId]=useState('');
  const watches=useQuery({queryKey:['dark-web-watches'],queryFn:api.darkWebWatches,retry:false});
  const results=useQuery({queryKey:['dark-web-results',selected,offset],queryFn:()=>api.darkWebResults(selected,PAGE_SIZE,offset),enabled:Boolean(selected),retry:false});
  const normalizedKeyword=keyword.trim().replace(/\s+/g,' '),duplicateKeyword=Boolean(watches.data?.items.some(w=>w.keyword.toLocaleLowerCase()===normalizedKeyword.toLocaleLowerCase()));
  const create=useMutation({mutationFn:api.createDarkWebWatch,onSuccess:()=>{setKeyword('');void watches.refetch()}});
  const toggle=useMutation({mutationFn:({id,enabled}:{id:string;enabled:boolean})=>api.patchDarkWebWatch(id,enabled),onSuccess:()=>void watches.refetch()});
  const scan=useMutation({mutationFn:api.scanDarkWebWatch,onSuccess:(value,watchId)=>{setJobWatchId(watchId);setJob(value)}});
  const active=watches.data?.items.find(w=>w.watch_id===selected),activeJob=Boolean(job&&!TERMINAL_STATES.includes(job.state)),actionError=create.error||toggle.error||scan.error;
  return <section className="page-section dark-web-page">
    <div className="section-heading"><div><span className="eyebrow">{t('darkScope')}</span><h2>{t('darkWeb')}</h2><p>{t('darkDescription')}</p></div></div>
    {can('analyst')&&<form className="watch-form" onSubmit={e=>{e.preventDefault();if(!create.isPending&&!duplicateKeyword&&window.confirm(t('confirmCreateWatch')))create.mutate(normalizedKeyword)}}><label htmlFor="watch-keyword">{t('watchKeyword')}</label><input id="watch-keyword" value={keyword} minLength={2} maxLength={100} onChange={e=>setKeyword(e.target.value)}/><button disabled={create.isPending||normalizedKeyword.length<2||duplicateKeyword}>{t('add')}</button>{duplicateKeyword&&<span role="alert">{t('duplicateWatch')}</span>}</form>}
    {actionError&&<div role="alert">{safeActionError(actionError,t)}</div>}
    {watches.isLoading&&<LoadingState/>}
    {watches.isError&&(watches.error instanceof ApiError&&watches.error.status===503?<div role="alert">{t('darkWebUnavailable')}</div>:<ErrorState onRetry={()=>void watches.refetch()}/>)}
    {watches.data?.items.length===0&&<EmptyState label={t('noWatches')}/>}
    <div className="watch-grid">{watches.data?.items.map(w=><article key={w.watch_id}><button onClick={()=>{setSelected(w.watch_id);setOffset(0)}}><strong>{w.keyword}</strong><span>{t('newCount',{count:number(w.new_result_count)})} · {t('totalCount',{count:number(w.result_count)})}</span></button><small>{w.last_scan_at?t('lastScanAt',{value:dateTime(w.last_scan_at)}):t('notScannedYet')}</small>{can('analyst')&&<><button disabled={scan.isPending||!w.enabled||(activeJob&&jobWatchId===w.watch_id)} onClick={()=>window.confirm(t('confirmScan'))&&scan.mutate(w.watch_id)}>{t('scanNow')}</button><button disabled={toggle.isPending||(activeJob&&jobWatchId===w.watch_id)} onClick={()=>window.confirm(t(w.enabled?'confirmDisableWatch':'confirmEnableWatch'))&&toggle.mutate({id:w.watch_id,enabled:!w.enabled})}>{t(w.enabled?'disable':'enable')}</button></>}</article>)}</div>
    {job&&<JobMonitor key={job.job_id} sourceId={jobWatchId} job={job} onUpdate={(watchId,value)=>{
      setJob(current=>current?.job_id===value.job_id?value:current);
      if(TERMINAL_STATES.includes(value.state)){void watches.refetch();if(selected===watchId)void results.refetch()}
    }}/>}
    {selected&&<section><h3>{t('results')}</h3>{results.isLoading&&<LoadingState/>}{results.isError&&<ErrorState onRetry={()=>void results.refetch()}/>} {results.data?.items.length===0&&<EmptyState label={t('noApprovedMatches')}/>} {results.data?.items.map(r=><Result key={r.result_id} item={r} keyword={active?.keyword||''}/>)}{results.data&&results.data.total>0&&<nav className="pagination" aria-label={t('results')}><button disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-PAGE_SIZE))}>{t('previous')}</button><span>{t('pageRange',{start:number(offset+1),end:number(Math.min(offset+results.data.items.length,results.data.total)),total:number(results.data.total)})}</span><button disabled={offset+PAGE_SIZE>=results.data.total} onClick={()=>setOffset(offset+PAGE_SIZE)}>{t('next')}</button></nav>}</section>}
  </section>
}
