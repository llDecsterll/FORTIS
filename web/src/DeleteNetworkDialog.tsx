import {useEffect,useRef,useState} from 'react';
import {api} from './api';
export function DeleteNetworkDialog({network,onClose,onDeleted}:{network:any;onClose:()=>void;onDeleted:()=>void}) {
  const dialog=useRef<HTMLDialogElement>(null);
  const [info,setInfo]=useState<any>(null),[error,setError]=useState(''),[confirmation,setConfirmation]=useState(''),[busy,setBusy]=useState(false);
  useEffect(()=>{dialog.current?.showModal();let active=true;api.networkDeletion(network.id).then(r=>{if(active)setInfo(r)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[network.id]);
  return <dialog ref={dialog} role="alertdialog" aria-labelledby="delete-network-title" aria-describedby="delete-network-description" className="network-delete-dialog" onCancel={e=>{e.preventDefault();if(!busy)onClose()}}>
    <h2 id="delete-network-title">Удалить сеть?</h2>
    <p><strong>{network.name}</strong> · {network.cidr}<br/>{network.contour==='SITES'?'Объекты':'Сотрудники'}</p>
    <p id="delete-network-description">Будут удалены запись каталога и связанные правила доступа этого контура. Конфигурации на сервере обновятся. Объекты, ключи и настройки роутеров сохранятся. Установленные клиентские конфигурации автоматически не обновляются.</p>
    {!info&&!error&&<p role="status">Проверяем связанные доступы…</p>}
    {info&&<><p>Правил доступа: <strong>{info.policies}</strong>. Конфигураций для обновления: <strong>{info.configs}</strong>.</p>
      {!!info.blockers.length?<div role="alert">{info.blockers.map((s:string)=><p key={s}>{s}</p>)}</div>:<label>Для подтверждения введите {info.cidr}<input value={confirmation} onChange={e=>setConfirmation(e.target.value)} autoComplete="off" disabled={busy}/></label>}</>}
    {error&&<p className="error-state" role="alert">{error}</p>}
    <div className="h-row"><button className="btn secondary" autoFocus disabled={busy} onClick={onClose}>Отмена</button><button className="btn danger" disabled={busy||!info||info.blockers.length>0||confirmation!==info.cidr} onClick={async()=>{
      setBusy(true);setError('');try{await api.deleteNetwork(network.id,confirmation,info.revision);onDeleted()}catch(e:any){setError(e.message);setBusy(false)}
    }}>{busy?'Удаление…':'Удалить сеть'}</button></div>
  </dialog>;
}
