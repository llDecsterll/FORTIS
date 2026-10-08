import {channelData, chartPath} from './channel-metrics.mjs';
import './network-channels.css';

const rate=(value:number|null)=>value===null?'—':value.toLocaleString('ru-RU',{maximumFractionDigits:2,minimumFractionDigits:2});
export function NetworkChannels({channels}:{channels:any}) {
  const cards=[{title:'Сотрудники',key:'Employees'},{title:'Объекты',key:'Sites'}].map(c=>{
    const data=channelData(channels,c.key);
    return {...c,...data,unavailable:data.stale||data.rx===null||data.tx===null};
  });
  const ceiling=Math.max(1,...cards.flatMap(c=>c.history.flatMap((r:any)=>[r.rx,r.tx])));
  return <section className="live-card network-channels" aria-label="Нагрузка двух сетевых каналов">
    <div className="card-head"><div><h2>Нагрузка каналов</h2><p className="channel-subtitle">Два контура · общая шкала трафика</p></div><span className="period-label">Последние 30 минут</span></div>
    <div className="channel-pair">{cards.map(c=><article className="channel-panel" key={c.key}>
      <div className="channel-heading"><h3>{c.title}</h3><span className={`channel-state${c.unavailable?' is-stale':''}`}><i aria-hidden="true" />{c.unavailable?'Нет свежих данных':'Данные обновляются'}</span></div>
      <div className="channel-rates"><div><span className="channel-receive-label"><i aria-hidden="true" />Приём сервером</span><strong>{rate(c.stale?null:c.rx)} <small>Мбит/с</small></strong></div><div><span className="channel-transmit-label"><i aria-hidden="true" />Передача сервером</span><strong>{rate(c.stale?null:c.tx)} <small>Мбит/с</small></strong></div><div className="channel-bandwidth"><span>Ёмкость канала</span><strong>{c.capacity?rate(c.capacity):'—'} <small>Мбит/с</small></strong></div></div>
      <div className="channel-chart" role="img" aria-label={`Трафик канала «${c.title}»: приём — синяя сплошная линия, передача — бирюзовый пунктир. Шкала до ${rate(ceiling)} Мбит/с.${c.unavailable?' Свежих данных нет.':''}`}>
        <div className="channel-axis"><span>{rate(ceiling)} Мбит/с</span><span>Приём ━ &nbsp; Передача ┄</span></div>
        {c.history.length>1?<svg viewBox="0 0 600 80" preserveAspectRatio="none" aria-hidden="true"><path d="M0 6H600 M0 41H600 M0 76H600" className="channel-grid"/><path d={chartPath(c.history,'rx',ceiling)} className="channel-line"/><path d={chartPath(c.history,'tx',ceiling)} className="channel-line channel-transmit"/></svg>:<p className="channel-empty">График появится после двух замеров</p>}
        <div className="channel-axis"><span>0 Мбит/с</span><span>{Number.isFinite(c.at)?`Замер ${new Date(c.at).toLocaleTimeString('ru-RU',{timeZone:'Europe/Moscow'})} МСК`:'Ожидание замеров'}</span></div>
      </div>
      <div className="channel-capacity">{c.capacity?<><span>Загрузка <b>{c.util===null?'—':rate(c.util)+'%'}</b></span>{c.util!==null?<progress max="100" value={Math.min(c.util,100)} aria-label={`Загрузка канала: ${c.title}`}/>:<span className="channel-capacity-track" aria-hidden="true" />}<span>{rate(c.capacity)} Мбит/с</span></>:'Пропускная способность не задана — процент загрузки недоступен'}</div>
    </article>)}</div>
    <p className="channel-note">Фактический трафик сетевых интерфейсов сервера, включая служебный. Приём и передача показаны отдельно, шкала графиков общая. Загрузка рассчитана относительно скорости канала из настроек мониторинга; при значении 0 используется скорость сетевой карты. Это не проверка скорости интернета.</p>
  </section>;
}
