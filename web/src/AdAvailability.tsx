import {useState} from 'react';
import {api} from './api';

type Result = {status:'AVAILABLE'|'UNAVAILABLE';detail:string;checkedAt:string;durationMs:number};

export function AdAvailability({id,disabled}:{id:string;disabled:boolean}) {
  const [result,setResult]=useState<Result|null>(null);
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  return <div aria-busy={busy}>
    <p role="status" aria-live="polite">
      <span className={`pill ${busy||!result?'info':result.status==='AVAILABLE'?'ok':'bad'}`}>
        {busy?'Проверяется…':error?'Проверка не выполнена':!result?'Не проверялся':result.status==='AVAILABLE'?'Доступен':'Недоступен'}
      </span>
      {result&&!busy&&!error&&<> · Проверено {new Date(result.checkedAt).toLocaleString('ru-RU',{timeZone:'Europe/Moscow'})} МСК · {result.durationMs} мс</>}
    </p>
    {result&&!busy&&!error&&<p>{result.detail}</p>}
    {error&&<p className="err" role="alert">{error}</p>}
    <p className="muted">Проверка соединения с портом LDAP/LDAPS с VPN-сервера. Пароль, права AD и синхронизация не проверяются. Статус отражает последний замер.</p>
    <button type="button" className="btn ghost" disabled={disabled||busy} onClick={async()=>{
      setBusy(true);setError('');setResult(null);
      try {setResult(await api.checkAd(id))}catch(e:any){setError(e.message||'Не удалось выполнить проверку')}finally{setBusy(false)}
    }}>{busy?'Проверка…':'Проверить доступность'}</button>
  </div>;
}
