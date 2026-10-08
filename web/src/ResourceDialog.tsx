import {useEffect,useRef,useState} from 'react';
import {api} from './api';
export function ResourceDialog({resource,networks,remove,onClose,onSaved}:{resource:any;networks:any[];remove:boolean;onClose:()=>void;onSaved:()=>void}) {
  const ref=useRef<HTMLDialogElement>(null);
  const [form,setForm]=useState({...resource,protocol:resource.protocol||"TCP"}),[error,setError]=useState(''),[busy,setBusy]=useState(false),[confirmation,setConfirmation]=useState('');
  useEffect(()=>{ref.current?.showModal()},[]);
  const field=(key:string,value:any)=>setForm({...form,[key]:value});
  return <dialog ref={ref} className="network-delete-dialog" role={remove?'alertdialog':'dialog'} aria-labelledby="resource-title" onCancel={e=>{e.preventDefault();if(!busy)onClose()}}>
    <form className="form-grid" onSubmit={async e=>{e.preventDefault();if(busy)return;setBusy(true);setError('');try{
      if(remove)await api.deleteResource(resource.id,confirmation);
      else {const payload={...form,port:form.port===''||form.port==null?null:Number(form.port),networkId:form.networkId||null};if(resource.id)await api.updateResource(resource.id,payload);else await api.createResource(payload)}
      onSaved();
    }catch(e:any){setError(e.message)}finally{setBusy(false)}}}>
      <h2 id="resource-title" className="span-2">{remove?'Удалить ресурс?':resource.id?'Редактировать ресурс':'Добавить ресурс'}</h2>
      {remove?<><p className="span-2">Будет удалена запись «{resource.name}». Сам сервер или сервис не удаляется. Связанные доступы защищены от удаления.</p><label className="span-2">Введите название ресурса<input autoFocus value={confirmation} onChange={e=>setConfirmation(e.target.value)} disabled={busy}/></label></>:<>
        <label>Название<input autoFocus required maxLength={200} value={form.name} onChange={e=>field('name',e.target.value)} disabled={busy}/></label>
        <label>Контур<select value={form.contour} disabled={busy||!!resource.id} onChange={e=>setForm({...form,contour:e.target.value,networkId:''})}><option value="EMPLOYEES">Сотрудники</option><option value="SITES">Объекты</option></select></label>
        <label>IPv4-адрес<input required placeholder="192.168.3.10" value={form.host} onChange={e=>field('host',e.target.value)} disabled={busy}/></label>
        <label>Порт<input required type="number" min={1} max={65535} value={form.port??''} onChange={e=>field('port',e.target.value)} disabled={busy}/></label>
        <label>Протокол<select value={form.protocol} disabled={busy} onChange={e=>field('protocol',e.target.value)}><option value="TCP">TCP</option><option value="UDP">UDP</option></select></label>
        <label>Тип<input required maxLength={50} value={form.kind} onChange={e=>field('kind',e.target.value)} disabled={busy}/></label>
        <label>Сеть<select value={form.networkId||''} disabled={busy} onChange={e=>field('networkId',e.target.value)}><option value="">Без привязки</option>{networks.filter(n=>n.contour===form.contour).map(n=><option key={n.id} value={n.id}>{n.name} · {n.cidr}</option>)}</select></label>
        <label className="span-2">Описание<input maxLength={2000} value={form.description||''} onChange={e=>field('description',e.target.value)} disabled={busy}/></label>
        <p className="muted span-2">Добавление в каталог не выдаёт VPN-доступ. Адрес используемого ресурса защищён от изменения.</p>
      </>}
      {error&&<p className="error-state span-2" role="alert">{error}</p>}
      <div className="h-row span-2"><button type="button" className="btn secondary" disabled={busy} onClick={onClose}>Отмена</button><button className={remove?'btn danger':'btn'} disabled={busy||(remove&&confirmation!==resource.name)}>{busy?'Сохраняем…':remove?'Удалить ресурс':'Сохранить ресурс'}</button></div>
    </form>
  </dialog>
}
