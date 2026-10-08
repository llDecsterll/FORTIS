(() => {
  const base=document.querySelector('meta[name="panel-base"]')?.content || '';
  window.panelBase=base;
  window.panelUrl=path=>{
    const url=new URL(path,location.href);
    if(url.origin!==location.origin || !base || url.pathname===base || url.pathname.startsWith(base+'/')) return url.href;
    url.pathname=base+url.pathname;
    return url.href;
  };
  window.panelRoute=(path=location.pathname)=>base && (path===base || path.startsWith(base+'/')) ? (path.slice(base.length)||'/') : path;
  localStorage.removeItem('kontur_token');
  const cookie = name => document.cookie.split('; ').find(v => v.startsWith(name+'='))?.split('=')[1] || '';
  window.fortisSessionMarker = () => cookie('fortis_session_kind') === 'setup' ? '' : cookie('fortis_session_hint');
  window.fortisClearSessionHint = () => {
    document.cookie='fortis_session_hint=; Max-Age=0; Path=/; SameSite=Strict';
    document.cookie='fortis_csrf=; Max-Age=0; Path=/; SameSite=Strict';
  };
  const original=window.fetch.bind(window);
  window.fetch=(input,options={})=>{
    const raw=input instanceof Request ? input.url : String(input);
    const url=new URL(window.panelUrl(raw),location.href);
    if(url.origin!==location.origin) return original(input,options);
    const request=input instanceof Request ? new Request(url,input) : url.href;
    const headers=new Headers(options.headers || (input instanceof Request ? input.headers : {}));
    const method=(options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if(!['GET','HEAD','OPTIONS'].includes(method)) {
      const csrf=cookie('fortis_csrf');
      if(csrf) headers.set('X-Fortis-CSRF',csrf);
    }
    return original(request,{...options,headers,credentials:'same-origin'});
  };
})();
