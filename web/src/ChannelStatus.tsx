import {useEffect,useState} from 'react';
import {api} from './api';

type Channel = {
  id:string; name:string; physicalInterface:string; wireguardInterface:string;
  status:string; physicalStatus:string; wireguardStatus:string; addresses:string[];
  lanSubnets:string[]; vpnAddresses:string[]; vpnSubnet:string; linkMbps:number|null;
  mtu:number|null; gateway:string|null; routeInterface:string|null; routeTable:number|string|null;
  fwmark:string; routeStatus:string; listenPort:number|null; peers:number|null; recentPeers:number|null;
  counters:Record<string,number|null>;
};
type Snapshot={checkedAt:string;channels:Channel[]};
const stateLabel=(state:string)=>state==='up'?'Работает':state==='warning'?'Требует проверки':'Недоступен';
const number=(n:number|string|null|undefined)=>n==null?'—':n.toLocaleString('ru-RU');
const bytes=(n:number|null|undefined)=>n==null?'—':`${(n/1024**3).toLocaleString('ru-RU',{maximumFractionDigits:2})} ГиБ`;
const moscow=(date:string)=>new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',dateStyle:'short',timeStyle:'medium'}).format(new Date(date))+' МСК';

export function ChannelStatus(){
  const [data,setData]=useState<Snapshot|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [refresh,setRefresh]=useState(0);
  useEffect(()=>{
    let active=true,pending=false;
    const load=async()=>{
      if(pending)return;
      pending=true;if(active)setBusy(true);
      try {const out=await api.channelStatus();if(active){setData(out);setError('');}}
      catch(e:any){if(active)setError(e.message||'Не удалось получить состояние каналов');}
      finally {pending=false;if(active)setBusy(false);}
    };
    load();const timer=window.setInterval(load,15000);
    return()=>{active=false;window.clearInterval(timer);};
  },[refresh]);
  return <section id="channel-status" className="channel-status" aria-labelledby="channel-state-title">
    <div className="channel-state-heading"><div><h3 id="channel-state-title">Состояние каналов сервера</h3><p className="settings-field-help">Физические интерфейсы, VPN-подсети и маршруты — фактические данные сервера.</p></div><button type="button" className="btn" disabled={busy} onClick={()=>setRefresh(n=>n+1)}>{busy?'Обновление…':'Обновить состояние каналов'}</button></div>
    {error&&<p className="err" role="alert">{error}{data?' Показан предыдущий замер.':''}</p>}
    {!data&&<p role="status">{error?'Данные недоступны.':'Загрузка состояния каналов…'}</p>}
    <div className="channel-state-grid">{data?.channels.map(c=><article className={`channel-state-card channel-${c.id}`} key={c.id}>
      <header><h4>{c.name}</h4><span className={`settings-tag ${c.status==='up'?'is-success':'is-warning'}`}>{stateLabel(c.status)}</span></header>
      <div className="channel-route"><div><span>Сетевая карта</span><strong>{c.physicalInterface}</strong><small>{stateLabel(c.physicalStatus)}</small></div><span aria-hidden="true">↔</span><div><span>WireGuard</span><strong>{c.wireguardInterface}</strong><small>{stateLabel(c.wireguardStatus)}</small></div></div>
      <dl className="channel-details">
        <dt>LAN-адрес сервера</dt><dd>{c.addresses?.join(', ')||'—'}</dd>
        <dt>Подсеть физического канала</dt><dd>{c.lanSubnets?.join(', ')||'—'}</dd>
        <dt>VPN-подсеть</dt><dd>{c.vpnSubnet}</dd>
        <dt>VPN-адрес сервера</dt><dd>{c.vpnAddresses?.join(', ')||'—'}</dd>
        <dt>Шлюз VPN-канала</dt><dd>{c.gateway||'—'}</dd>
        <dt>Маршрут VPN-трафика</dt><dd>{c.routeInterface||'—'} · таблица {number(c.routeTable)} · {c.fwmark}</dd>
        <dt>Маршрут настроен</dt><dd>{c.routeStatus==='valid'?'Да':'Требует проверки'}</dd>
        <dt>UDP-порт / MTU</dt><dd>{number(c.listenPort)} / {number(c.mtu)}</dd>
        <dt>Скорость сетевой карты</dt><dd>{c.linkMbps?`${number(c.linkMbps)} Мбит/с`:'Не определена'}</dd>
        <dt>Peers / свежие рукопожатия</dt><dd>{number(c.peers)} / {number(c.recentPeers)}</dd>
        <dt>Принято / передано</dt><dd>{bytes(c.counters?.rxBytes)} / {bytes(c.counters?.txBytes)}</dd>
        <dt>Ошибки RX / TX</dt><dd>{number(c.counters?.rxErrors)} / {number(c.counters?.txErrors)}</dd>
        <dt>Отброшено RX / TX</dt><dd>{number(c.counters?.rxDropped)} / {number(c.counters?.txDropped)}</dd>
      </dl>
    </article>)}</div>
    {data&&<p className="settings-field-help channel-check-time">Обновлено: {moscow(data.checkedAt)}. Свежие рукопожатия — за последние 3 минуты. Счётчики накопительные с запуска интерфейса, а не скорость и не новые ошибки.</p>}
    <div className="channel-speed-test"><div><h3>Проверка скорости интернета — 2ip</h3><p>Тест выполняется в вашем браузере и не измеряет автоматически два канала VPN-сервера. При split-tunnel он может проверять ваше обычное интернет-соединение, минуя VPN.</p><p>Скорость сетевой карты выше — не скорость интернета. Статус «Работает» подтверждает интерфейсы и маршрут, но не доступность всех ресурсов. Замер скорости может временно нагрузить канал; сервис увидит ваш внешний IP.</p></div><a className="btn marking" href="https://2ip.io/ru/speed/" target="_blank" rel="noopener noreferrer">Открыть тест скорости на 2ip</a></div>
  </section>;
}
