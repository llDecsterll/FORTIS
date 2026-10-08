export function mbps(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value * 8 / 1000000 : null;
}
export function metricTime(value) {
  if (typeof value !== 'string') return NaN;
  return Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : value + 'Z');
}
export function channelData(channels, suffix, clock = Date.now()) {
  const row = channels?.now;
  const at = metricTime(row?.at);
  const stale = !Number.isFinite(at) || clock - at > 90000 || at - clock > 90000;
  const rx = mbps(row?.[`nic${suffix}RxBps`]);
  const tx = mbps(row?.[`nic${suffix}TxBps`]);
  const capacity = row?.[`nic${suffix}Mbps`] > 0 ? row[`nic${suffix}Mbps`] : null;
  const history = (channels?.history || []).map(r => ({at:metricTime(r.at),rx:mbps(r[`nic${suffix}RxBps`]),tx:mbps(r[`nic${suffix}TxBps`])})).filter(r => Number.isFinite(r.at) && r.rx !== null && r.tx !== null).sort((a,b)=>a.at-b.at);
  return {rx,tx,capacity,stale,at,history,util:!stale && rx !== null && tx !== null && capacity ? Math.max(rx,tx)/capacity*100 : null};
}
export function chartPath(history, key, ceiling) {
  if(history.length<2) return '';
  const start=history[0].at, span=history.at(-1).at-start;
  if(span<=0 || ceiling<=0) return '';
  return history.map((row,i)=>`${i?'L':'M'}${((row.at-start)/span*600).toFixed(2)},${(76-Math.min(row[key]/ceiling,1)*70).toFixed(2)}`).join(' ');
}
