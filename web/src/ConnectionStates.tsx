export const connectionLabels:Record<string,string>={online:'В сети',offline:'Не в сети',blocked:'Заблокированы'};
export function StatusFilters({value,onChange,title}:{value:string;onChange:(state:string)=>void;title:string}) {
  return <div className="connection-filters" role="group" aria-label={`Статус: ${title}`}>{Object.entries(connectionLabels).map(([key,label])=><button type="button" key={key} aria-pressed={value===key} onClick={()=>onChange(key)}>{label}</button>)}</div>;
}
export function ConnectionStates({title,counts,value,onChange}:{title:string;counts:any;value:string;onChange:(state:string)=>void}) {
  const valid=Object.keys(connectionLabels).every(key=>Number.isFinite(counts?.[key])&&counts[key]>=0);
  const total=valid?Object.keys(connectionLabels).reduce((n,key)=>n+counts[key],0):null;
  return <div className="connection-summary"><div className="k">{title}</div>
    <div className="summary-total connection-total" aria-label={`${title}: в сети ${valid?counts.online:'нет данных'}, всего ${total??'нет данных'} с выданным VPN`}>
      <strong>{valid?counts.online:'—'}</strong><span className="summary-denominator">/ {total??'—'}</span><span className="summary-caption">в сети</span>
    </div>
    <div className="state-distribution" aria-hidden="true">{total!==null&&total>0&&Object.keys(connectionLabels).filter(key=>counts[key]>0).map(key=><span key={key} className={`state-${key}`} style={{flexGrow:counts[key]}} />)}</div>
    <div className="connection-counts" role="group" aria-label={`Фильтр: ${title}`}>
    {Object.entries(connectionLabels).map(([key,label])=><button type="button" key={key} className={`count-${key}`} aria-label={`${title}: ${label}`} title={label} aria-pressed={value===key} onClick={()=>onChange(key)}><span><i aria-hidden="true" />{key==='blocked'?'Блок.':label}</span><strong>{valid?counts[key]:'—'}</strong></button>)}
    </div><div className="s">С выданным VPN · выберите статус</div></div>;
}
