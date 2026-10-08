import {metricTime,mbps} from './channel-metrics.mjs';
const format=(n:number|null)=>n===null?'—':n.toLocaleString('ru-RU',{maximumFractionDigits:1});
export function TrafficSummary({channels}:{channels:any}) {
  const now=channels?.now;
  const fresh=Number.isFinite(metricTime(now?.at))&&Math.abs(Date.now()-metricTime(now.at))<90000;
  const rates=['wgEmployeesRxBps','wgEmployeesTxBps','wgSitesRxBps','wgSitesTxBps'].map(k=>fresh?mbps(now?.[k]):null);
  const total=rates.every(n=>n!==null)?rates.reduce<number>((a,b)=>a+(b??0),0):null;
  return <div className="traffic-summary"><div className="k">Трафик WireGuard</div>
    <div className="summary-total"><strong>{format(total)}</strong><span className="summary-unit">Мбит/с</span></div>
    <div className="traffic-breakdown"><div className="traffic-legend"><span>Контур</span><span>↓ Приём</span><span>↑ Отдача</span></div>
      {['Сотрудники','Объекты'].map((name,i)=><div key={name}><span>{name}</span><b>{format(rates[i*2])}</b><b>{format(rates[i*2+1])}</b></div>)}
    </div><div className={`s${total===null?' metric-unavailable':''}`}>{total===null?'Нет свежего замера трафика':'Приём + отдача · оба VPN-контура'}</div></div>;
}
