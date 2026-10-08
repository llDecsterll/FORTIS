async function api(path, body) {
  const token = window.fortisSessionMarker?.() || '';
  const response = await fetch(path, {method:body?'PATCH':'GET',cache:'no-store',headers:{...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  const data = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(data?.error?.message || (typeof data.detail==='string'?data.detail:'Не удалось сохранить объект'));
  return data;
}
function el(tag,text,cls) { const n=document.createElement(tag); if(text)n.textContent=text; if(cls)n.className=cls; return n; }
export async function editSite(id) {
  const modal=el('dialog','','workflow-dialog account-card'); modal.setAttribute('aria-label','Редактировать объект');
  const head=el('div','','workflow-dialog-head'); head.append(el('h2','Редактировать объект'));
  const close=el('button','×','btn ghost'); close.type='button'; close.setAttribute('aria-label','Закрыть редактирование'); close.onclick=()=>modal.close();head.append(close);
  const form=el('form','','workflow-dialog-body'); const error=el('p','Загрузка…'); error.setAttribute('role','alert'); form.append(error);
  modal.append(head,form);document.body.append(modal);modal.addEventListener('close',()=>modal.remove());modal.showModal();
  let site;try {site=await api(`/api/sites/${encodeURIComponent(id)}`);}catch(e){error.textContent=e.message;return;}
  if(!modal.isConnected)return;error.textContent='';
  const fields={};
  for(const [key,title] of [['name','Название объекта'],['address','Адрес объекта'],['lanCidr','LAN-подсети роутера'],['routerName','Название роутера'],['providerName','Название провайдера'],['providerPhone','Телефон провайдера'],['providerEmail','Почта провайдера'],['notes','Примечание']]) {
    const label=el('label','','field'); const input=el(key==='notes'?'textarea':'input');input.name=key;input.value=site[key]||'';input.required=['name','lanCidr'].includes(key);input.maxLength=key==='notes'?4000:key==='lanCidr'?2048:key==='address'?500:200;
    if(key==='lanCidr'){input.placeholder='192.168.75.0/24';input.readOnly=!!site.hasConfig;input.spellcheck=false;}
    if(key==='providerPhone'){input.type='tel';input.maxLength=64;}
    if(key==='providerEmail'){input.type='email';input.maxLength=254;}
    label.append(el('span',title),input);form.append(label);fields[key]=input;
  }
  form.append(el('p',site.hasConfig?'VPN уже выдан. LAN изменяется через настройку роутера вместе с маршрутами сервера. Здесь можно изменить остальные сведения.':'Укажите адрес сети и маску, например 192.168.75.0/24. Несколько подсетей — через запятую. Сохранение не согласовывает заявку.','muted'));
  const actions=el('div','','toolbar');const cancel=el('button','Отмена','btn ghost');cancel.type='button';cancel.onclick=()=>modal.close();const save=el('button','Сохранить изменения','btn');save.type='submit';actions.append(cancel,save);form.append(error,actions);
  form.onsubmit=async event=>{event.preventDefault();save.disabled=true;error.textContent='';
    try {await api(`/api/sites/${encodeURIComponent(id)}`,Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value])));modal.close();location.reload();}
    catch(e){error.textContent=e.message;fields.lanCidr.setAttribute('aria-invalid',String(/подсет|LAN|маск|сети/i.test(e.message)));}
    finally{save.disabled=false;}
  };
}

export function siteForRow(row, sites) {
  return sites.find(site => site.id === row.dataset.siteId);
}
let root=null,loading=false,sites=[],signature='';
async function enhance() {
  const heading=[...document.querySelectorAll('h1')].find(n=>n.textContent.trim()==='Объекты');
  if(!heading){root=null;sites=[];signature='';return;}
  const nextSignature=[...document.querySelectorAll('tr[data-site-id]')].map(r=>r.dataset.siteId).join('\n');
  if((root!==heading||signature!==nextSignature)&&!loading){root=heading;signature=nextSignature;loading=true;try {
    const me=await api('/api/auth/me'); if(!['ADMIN','IT_LEAD','IT_STAFF'].includes(me.role))return;
    sites=(await api('/api/sites')).data;
  }catch{return;}finally{loading=false;}}
  for(const row of document.querySelectorAll('tr[data-site-id]')) {
    if(row.querySelector('[data-edit-site]'))continue;
    const cells=row.querySelectorAll('td');if(cells.length<2)continue;
    const site=siteForRow(row,sites);
    if(!site)continue;
    const button=el('button','Редактировать','btn ghost tiny');button.type='button';button.dataset.editSite=site.id;button.setAttribute('aria-label',`Редактировать объект ${site.name}`);button.onclick=event=>{event.stopPropagation();editSite(site.id);};
    (cells[cells.length-1].querySelector('.toolbar')||cells[cells.length-1]).prepend(button);
  }
}
if(typeof document!=='undefined'){
  let queued=false;new MutationObserver(()=>{if(!queued){queued=true;queueMicrotask(()=>{queued=false;enhance();});}}).observe(document.body,{childList:true,subtree:true});enhance();
}
