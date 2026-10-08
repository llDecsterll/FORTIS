import {useEffect,useRef,useState} from 'react';
import {api} from './api';
import type {AdConfig,AdDomain} from './AdSettings';

export function AdDomainEditor({domain,config,onClose,onSaved}:{domain:AdDomain|'new';config:AdConfig;onClose:()=>void;onSaved:(v:AdConfig)=>void}) {
  const dialog=useRef<HTMLDialogElement>(null);
  const [form,setForm]=useState({...domain==='new'?{id:'',host:'',port:389,useSsl:false,bindDn:'',baseDn:'',passwordSet:false}:domain,password:''});
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  useEffect(()=>{dialog.current?.showModal()},[]);
  return <dialog ref={dialog} className="network-delete-dialog ad-dialog" aria-labelledby="ad-edit-title" onCancel={e=>{e.preventDefault();if(!busy)onClose()}}>
    <h2 id="ad-edit-title">{domain==='new'?'Добавить домен AD':'Редактировать домен AD'}</h2>
    <form className="form-grid" onSubmit={async e=>{
      e.preventDefault();setBusy(true);setError('');
      try {
        const sources=domain==='new'?[...config.sources,form]:config.sources.map(s=>s.id===form.id?form:s);
        onSaved(await api.saveAd({sources,revision:config.revision}));
      }catch(ex:any){setError(ex.message);setBusy(false)}
    }}>
      <fieldset className="span-2 form-grid" disabled={busy}>
        <label className="field"><span>Сервер домена</span><input autoFocus required value={form.host} onChange={e=>setForm({...form,host:e.target.value})}/></label>
        <label className="field"><span>Порт</span><input type="number" min="1" max="65535" required value={form.port} onChange={e=>setForm({...form,port:Number(e.target.value)})}/></label>
        <label className="field span-2"><span>Учётная запись AD</span><input required value={form.bindDn} autoComplete="off" onChange={e=>setForm({...form,bindDn:e.target.value})}/></label>
        <label className="field span-2"><span>Пароль AD</span><input type="password" autoComplete="new-password" required={!form.passwordSet} value={form.password} placeholder={form.passwordSet?'Оставьте пустым, чтобы сохранить пароль':''} onChange={e=>setForm({...form,password:e.target.value})}/></label>
        <label className="span-2"><input type="checkbox" checked={form.useSsl} onChange={e=>setForm({...form,useSsl:e.target.checked,port:e.target.checked?636:389})}/> Защищённое подключение LDAPS</label>
        <label className="field span-2"><span>Папка (Base DN)</span><input required value={form.baseDn} onChange={e=>setForm({...form,baseDn:e.target.value})}/></label>
      </fieldset>
      {error&&<p className="err span-2" role="alert">{error}</p>}
      <div className="toolbar span-2"><button type="button" className="btn ghost" disabled={busy} onClick={onClose}>Отмена</button><button className="btn marking" disabled={busy}>{busy?'Сохранение…':'Сохранить домен'}</button></div>
    </form>
  </dialog>;
}

export function AdDeleteDialog({domain,onClose,onDeleted}:{domain:AdDomain;onClose:()=>void;onDeleted:(v:any)=>void}) {
  const dialog=useRef<HTMLDialogElement>(null);
  const [info,setInfo]=useState<any>(null),[error,setError]=useState('');
  const [confirmation,setConfirmation]=useState(''),[busy,setBusy]=useState(false);
  useEffect(()=>{dialog.current?.showModal();let active=true;api.adDeletion(domain.id).then(out=>{if(active)setInfo(out)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[domain.id]);
  return <dialog ref={dialog} className="network-delete-dialog ad-dialog" role="alertdialog" aria-labelledby="ad-delete-title" aria-describedby="ad-delete-description" onCancel={e=>{e.preventDefault();if(!busy)onClose()}}>
    <h2 id="ad-delete-title">Удалить домен {domain.host}?</h2>
    <p id="ad-delete-description">Будут удалены импортированные из этого домена сотрудники, их устройства, VPN-ключи и конфигурации, сертификаты, сессии, заявки и документы. Действующие подключения будут отключены. Отмена после подтверждения невозможна.</p>
    <p className="muted">Сам каталог AD не изменяется. Другие домены, локальные пользователи, объекты и общие справочники сохраняются. Журнал аудита сохраняется. Скачанные файлы остаются на компьютерах, но ключи больше не дают доступа.</p>
    {!info&&!error&&<p role="status">Проверка связанных записей…</p>}
    {info&&<>
      <p>Сотрудников: <strong>{info.users.length}</strong> · Устройств: <strong>{info.devices}</strong> · VPN-ключей: <strong>{info.keys}</strong> · Заявок: <strong>{info.requests}</strong> · Документов: <strong>{info.documents}</strong></p>
      {!!info.users.length&&<details><summary>Какие сотрудники будут удалены</summary><ul>{info.users.map((u:any)=><li key={u.id}>{u.name}</li>)}</ul></details>}
      {info.blockers.map((b:string)=><p className="err" role="alert" key={b}>{b}</p>)}
      {!info.blockers.length&&<label className="field"><span>Для подтверждения введите {info.host}</span><input autoComplete="off" value={confirmation} disabled={busy} onChange={e=>setConfirmation(e.target.value)}/></label>}
    </>}
    {error&&<p className="err" role="alert">{error}</p>}
    <div className="toolbar"><button autoFocus className="btn ghost" disabled={busy} onClick={onClose}>Отмена</button><button className="btn danger" disabled={busy||!info||!!info.blockers.length||confirmation!==info.host} onClick={async()=>{
      setBusy(true);setError('');
      try {onDeleted(await api.deleteAd(domain.id,confirmation,info.revision))}
      catch(e:any){setError(e.message);setInfo(null);setBusy(false)}
    }}>{busy?'Удаление и отзыв доступа…':'Удалить домен и доступы'}</button></div>
  </dialog>;
}
