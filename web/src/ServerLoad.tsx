import {metricTime} from './channel-metrics.mjs';
const amount=(n:number)=>typeof n==='number'&&Number.isFinite(n)?(n/1024**3).toLocaleString('ru-RU',{maximumFractionDigits:1,minimumFractionDigits:1}):'—';
export function ServerLoad({channels}:{channels:any}) {
  const now=channels?.now,mem=channels?.memory;
  const fresh=now && Number.isFinite(metricTime(now.at)) && Math.abs(Date.now()-metricTime(now.at))<90000;
  const cpu=fresh&&typeof now.cpuPercent==='number'&&Number.isFinite(now.cpuPercent)?now.cpuPercent:null;
  const memory=fresh&&mem&&Number.isFinite(mem.usedPercent)?mem:null;
  return <div className="server-load-details">
    <div className="k">Ресурсы сервера</div>
    <div className="resource-metric resource-cpu">
      <div className="summary-total"><strong>{cpu!==null?cpu.toLocaleString('ru-RU',{maximumFractionDigits:1}):'—'}</strong><span className="summary-unit">%</span><span className="summary-caption">ЦП</span></div>
      {cpu!==null?<progress aria-label="Загрузка процессора" max={100} value={Math.min(100,Math.max(0,cpu))} />:<div className="resource-track" aria-hidden="true" />}
    </div>
    <div className="resource-metric resource-memory"><div className="server-load-line"><span>Оперативная память</span><strong>{memory?`${memory.usedPercent.toLocaleString('ru-RU',{maximumFractionDigits:1})}%`:'—'}</strong></div>{memory?<progress aria-label="Использование оперативной памяти" max={100} value={Math.min(100,Math.max(0,memory.usedPercent))} />:<div className="resource-track" aria-hidden="true" />}</div>
    <div className="resource-capacity"><span>Занято <b>{memory?amount(memory.usedBytes):'—'}</b></span><span>из <b>{memory?amount(memory.totalBytes):'—'} ГиБ</b></span></div>
    <div className={`s${!memory||cpu===null?' metric-unavailable':''}`}>{!memory&&cpu===null?'Нет свежих замеров ЦП и памяти':cpu===null?'Нет свежего замера ЦП':memory?`Доступно ${amount(memory.availableBytes)} ГиБ`:'Нет свежих данных о памяти'}</div>
  </div>;
}
