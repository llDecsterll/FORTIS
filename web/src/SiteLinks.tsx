import {useEffect,useRef,useState} from 'react';
import {api} from './api';
export function SiteLinks({sites,canEdit}:{sites:any[];canEdit:boolean}) {
  const [rows,setRows]=useState<any[]>([]),[error,setError]=useState(''),[editing,setEditing]=useState<any>(null),[busy,setBusy]=useState(false),[notice,setNotice]=useState('');
  const ref=useRef<HTMLDialogElement>(null);
  const load=()=>api.siteLinks().then(r=>setRows(r.data)).catch(e=>setError(e.message));
  useEffect(()=>{load()},[sites]);
  useEffect(()=>{if(editing)ref.current?.showModal()},[editing!==null]);
  const eligible=sites.filter(s=>s.vpnIp&&s.lanCidr);
  return <section className="card" aria-label="Связи объектов">
    <div className="h-row"><h2>Связи объектов</h2>{canEdit&&<button className="btn" onClick={()=>{setError('');setEditing({siteA:'',siteB:'',lanA:'',lanB:''})}}>Связать объекты</button>}</div>
    <p className="muted">Двусторонний доступ между выбранными подсетями через VPN-сервер. После создания примените обновлённую конфигурацию на обоих роутерах. Это доступ по IP, а не объединение широковещательной сети.</p>
    {error&&<p className="error-state" role="alert">{error}</p>}{notice&&<p role="status">{notice}</p>}
    {!rows.length&&<p>Связей пока нет.</p>}
    {rows.map(r=><div className="net-item" key={r.id}><span><strong>{r.nameA} ↔ {r.nameB}</strong><small className="cell-detail">{r.lanA} ↔ {r.lanB}</small></span><span>{r.active?'Разрешена на сервере':r.enabled?'Не действует: проверьте VPN и подсети':'Отключена'}</span>{canEdit&&<div className="h-row"><button className="btn secondary" onClick={()=>{setError('');setEditing({...r,toggle:true})}}>{r.enabled?'Отключить связь':'Включить связь'}</button><button className="btn danger" onClick={()=>{setError('');setEditing({...r,toggle:true,remove:true})}}>Удалить связь</button></div>}</div>)}
    {editing&&<dialog ref={ref} className="network-delete-dialog" aria-labelledby="site-link-title" onCancel={e=>{e.preventDefault();if(!busy)setEditing(null)}}><form className="form-grid" onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{
      if(editing.remove)await api.deleteSiteLink(editing.id);else if(editing.toggle)await api.toggleSiteLink(editing.id,!editing.enabled);else await api.createSiteLink(editing);
      setNotice(editing.remove?'Связь удалена. Объекты и VPN-ключи сохранены. Обновите конфигурации на обоих роутерах.':'Настройки сервера сохранены. Новые конфигурации доступны в карточках обоих объектов. Примените их на роутерах.');setEditing(null);await load();
    }catch(e:any){setError(e.message)}finally{setBusy(false)}}}>
      <h2 id="site-link-title" className="span-2">{editing.remove?'Удалить связь?':editing.toggle?(editing.enabled?'Отключить связь?':'Включить связь?'):'Связать сети объектов'}</h2>
      {editing.toggle?<p className="span-2">{editing.nameA} · {editing.lanA} ↔ {editing.nameB} · {editing.lanB}</p>:['A','B'].map(side=><div key={side}><label>Объект {side}<select required disabled={busy} value={editing['site'+side]} onChange={e=>setEditing({...editing,['site'+side]:e.target.value,['lan'+side]:''})}><option value="">Выберите объект</option>{eligible.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label><label>Подсеть {side}<select required disabled={busy} value={editing['lan'+side]} onChange={e=>setEditing({...editing,['lan'+side]:e.target.value})}><option value="">Выберите подсеть</option>{(eligible.find(s=>s.id===editing['site'+side])?.lanCidr||'').split(',').map((n:string)=>n.trim()).filter(Boolean).map((n:string)=><option key={n}>{n}</option>)}</select></label></div>)}
      <p className="span-2">{editing.remove?'Связь исчезнет из списка, доступ между этими подсетями будет закрыт. Сами объекты, их подключения и VPN-ключи останутся. При необходимости связь можно создать заново.':editing.toggle&&editing.enabled?'Сервер заблокирует трафик между этими подсетями. VPN-ключи сохранятся.':'Будет разрешён трафик в обе стороны между выбранными подсетями. Другие объекты и сотрудники не включаются в эту связь.'}</p>
      {error&&<p className="error-state span-2" role="alert">{error}</p>}
      <div className="h-row span-2"><button type="button" className="btn secondary" disabled={busy} onClick={()=>setEditing(null)}>Отмена</button><button className={editing.remove?'btn danger':'btn'} disabled={busy}>{busy?'Применяем…':editing.remove?'Удалить связь':editing.toggle?'Подтвердить':'Создать связь'}</button></div>
    </form></dialog>}
  </section>
}
