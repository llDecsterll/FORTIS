import {useEffect, useState} from 'react';
import {api} from './api';
import {AdDomainEditor, AdDeleteDialog} from './AdDomainDialogs';
import {AdAvailability} from './AdAvailability';

export type AdDomain = {id: string; host: string; port: number; useSsl: boolean;
  bindDn: string; baseDn: string; passwordSet: boolean; deleting?: boolean};
export type AdConfig = {sources: AdDomain[]; revision: string};

export function AdSettings() {
  const [config,setConfig]=useState<AdConfig|null>(null);
  const [error,setError]=useState(''),[message,setMessage]=useState('');
  const [busy,setBusy]=useState(false);
  const [edit,setEdit]=useState<AdDomain|'new'|null>(null);
  const [remove,setRemove]=useState<AdDomain|null>(null);
  async function load() {
    setError('');
    try {setConfig(await api.adSettings())} catch(e:any) {setError(e.message)}
  }
  useEffect(()=>{void load()},[]);
  const deleting=config?.sources.some(s=>s.deleting);
  return <section id="settings-ad" className="card settings-section settings-ad" aria-labelledby="ad-title" aria-busy={busy}>
    <div className="settings-section-head"><span className="settings-section-index" aria-hidden="true">03</span><div><h2 id="ad-title">Active Directory</h2><p>Источники сотрудников и проверка соединения с доменами.</p></div>{config&&<span className="settings-tag">Доменов: {config.sources.length}</span>}</div>
    <p className="settings-note">Изменение подключения сохраняет ключи; удаление домена удаляет его сотрудников и отзывает их VPN-доступ.</p>
    {error&&<p className="err" role="alert">{error} <button className="btn ghost" onClick={load}>Повторить загрузку</button></p>}
    {message&&<p className="ok-msg" role="status">{message}</p>}
    {!config&&!error&&<p role="status">Загрузка доменов…</p>}
    {config&&<>
      {!config.sources.length&&<div className="settings-empty"><strong>Домены AD не добавлены</strong><p>Автоматический импорт отключён. Добавьте источник сотрудников, чтобы настроить синхронизацию.</p></div>}
      <div className="settings-domain-list">
      {config.sources.map(domain=><section className="ad-domain" key={domain.id} aria-label={`Домен ${domain.host}`}>
        <div className="settings-domain-head"><h3>{domain.host}:{domain.port}</h3><span className="settings-tag">{domain.useSsl?'LDAPS':'LDAP'}</span></div>
        <dl className="settings-domain-facts"><div><dt>Область импорта · Base DN</dt><dd>{domain.baseDn}</dd></div><div><dt>Учётная запись подключения</dt><dd>{domain.bindDn}</dd></div></dl>
        <div className="settings-domain-check"><AdAvailability key={`${domain.id}:${config.revision}`} id={domain.id} disabled={busy||!!domain.deleting}/></div>
        {domain.deleting&&<p className="err" role="alert">Удаление не завершено. Синхронизация этого домена остановлена. Повторите удаление.</p>}
        <div className="toolbar settings-domain-actions">
          <button className="btn ghost" disabled={busy||deleting} onClick={()=>setEdit(domain)}>Редактировать</button>
          <button className="btn danger" disabled={busy} onClick={()=>setRemove(domain)}>{domain.deleting?'Завершить удаление':'Удалить домен'}</button>
        </div>
      </section>)}
      </div>
      <div className="toolbar settings-ad-actions">
        <button className="btn marking" disabled={busy||deleting} onClick={()=>setEdit('new')}>Добавить домен</button>
        <button className="btn ghost" disabled={busy||!config.sources.length||deleting} onClick={async()=>{
          setBusy(true);setError('');setMessage('');
          try {const out=await api.syncAd();setMessage(`Синхронизация: создано ${out.created}, обновлено ${out.updated}, отключено ${out.disabled}.`);if(out.errors?.length)setError(out.errors.join(' '))}
          catch(e:any){setError(e.message)}finally{setBusy(false)}
        }}>{busy?'Синхронизация…':'Синхронизировать'}</button>
      </div>
      {edit&&<AdDomainEditor domain={edit} config={config} onClose={()=>setEdit(null)} onSaved={saved=>{setConfig(saved);setEdit(null);setMessage('Подключение AD сохранено.');setError('')}}/>}
      {remove&&<AdDeleteDialog domain={remove} onClose={()=>{setRemove(null);void load()}} onDeleted={out=>{setRemove(null);setMessage(`Домен удалён. Удалено сотрудников: ${out.users}, VPN-ключей: ${out.keys}.`);void load()}}/>}
    </>}
  </section>;
}
