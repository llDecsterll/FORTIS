// One request at a time; every mounted view owns and disposes its subscription.
export function startLiveRefresh(load, {env=window, interval=5000}={}) {
  let stopped=false, pending=false, timer;
  const tick=async()=>{
    if(stopped || pending) return;
    env.clearTimeout(timer);
    pending=true;
    try { await load(); } catch (_) { /* Keep last successful data. */ }
    finally { pending=false; if(!stopped) timer=env.setTimeout(tick,interval); }
  };
  env.addEventListener('focus',tick);
  env.addEventListener('online',tick);
  tick();
  return ()=>{stopped=true;env.clearTimeout(timer);env.removeEventListener('focus',tick);env.removeEventListener('online',tick);};
}

export async function checkRelease({version,fetch:request=fetch,notify=()=>{}}) {
  try {
    const response=await request('/version.json',{cache:'no-store'});
    if(!response.ok) return;
    const next=await response.json();
    if(typeof next.version!=='string' || !version || next.version===version) return;
    // Background polling must not replace an active page or reset its scroll position.
    notify();
  } catch (_) { /* Offline must not cause reload loops. */ }
}

export function watchRelease() {
  const version=document.querySelector('meta[name="app-version"]')?.content;
  let dirty=false;
  document.addEventListener('input',()=>{dirty=true});
  window.addEventListener('kontur:navigation',()=>{dirty=false});
  const busy=()=>dirty || !!document.querySelector('dialog[open], [role="dialog"], form:focus-within');
  const notify=()=>{
    if(document.getElementById('release-update')) return;
    const node=document.createElement('div');
    node.id='release-update'; node.className='release-update'; node.setAttribute('role','status');
    const text=document.createElement('span'); text.textContent='Доступна новая версия панели. Завершите ввод и обновите страницу.';
    const button=document.createElement('button'); button.className='btn'; button.textContent='Обновить панель';
    button.onclick=()=>{if(!busy() || window.confirm('Несохранённые данные будут потеряны. Обновить панель?')) location.reload()};
    node.append(text,button); document.body.append(node);
  };
  return startLiveRefresh(()=>checkRelease({version,notify}),{interval:30000});
}
