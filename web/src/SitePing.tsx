import { useState } from 'react';
import { api } from './api';
import { ipv4Number, lanHostAllowed } from './site-ping-targets.mjs';

export function SitePing({ site, externalIp }: { site: any; externalIp: string }) {
  const [host, setHost] = useState('');
  const [busy, setBusy] = useState('');
  const [results, setResults] = useState<Record<string, any>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const lan = site.lanCidr || '';
  const checks = [
    { key: 'vpn', title: 'VPN-IP роутера', ip: site.vpnIp || '' },
    { key: 'external', title: 'Внешний IP · последний endpoint', ip: externalIp },
    { key: 'lan', title: 'Устройство в локальной подсети', ip: host.trim() },
  ];
  async function run(key: string, ip: string) {
    if (busy) return;
    setErrors(prev => ({ ...prev, [key]: '' }));
    setResults(prev => ({ ...prev, [key]: null }));
    if (key === 'lan' && !lanHostAllowed(ip, lan)) {
      setErrors(prev => ({ ...prev, [key]: 'Введите IP устройства из указанной подсети, не адрес сети или broadcast.' }));
      return;
    }
    setBusy(key);
    try { const result = await api.pingNetwork(ip); setResults(prev => ({ ...prev, [key]: result })); }
    catch (error: any) { setErrors(prev => ({ ...prev, [key]: error.message || 'Не удалось выполнить проверку' })); }
    finally { setBusy(''); }
  }
  return <section aria-label="Проверка доступности объекта">
    <h3>Проверка доступности</h3>
    <p className="muted">Пинг с VPN-сервера: 3 пакета. Между запусками — 10 секунд. Проверки выполняются только по нажатию кнопки.</p>
    <div className="info-row"><span>Локальные подсети</span><b className="mono">{lan || 'Не указаны'}</b></div>
    {checks.map(check => <div key={check.key} className="access-block">
      <h4>{check.title}</h4>
      {check.key === 'lan' ? <label>IP устройства в подсети объекта<input value={host} maxLength={45} disabled={!!busy || !lan} placeholder="Введите IP компьютера или роутера" onChange={event => setHost(event.target.value)} /></label> : <p className="mono">{check.ip || 'Адрес пока неизвестен'}</p>}
      <button type="button" className="btn secondary" disabled={!!busy || ipv4Number(check.ip) === null || (check.key === 'lan' && !lan)} onClick={() => run(check.key, check.ip)} aria-label={`Пинг: ${check.title}`}>{busy === check.key ? 'Проверяем…' : 'Пинг'}</button>
      {errors[check.key] && <p className="error-state" role="alert">{errors[check.key]}</p>}
      <div role="status" aria-live="polite" aria-busy={busy === check.key}>
        {results[check.key] && <>
          <p><b className="mono">{results[check.key].ip}</b> · {results[check.key].reachable ? 'Есть ответ' : 'Нет ответа'} · Ответов: {results[check.key].received}/{results[check.key].sent} · Потери: {results[check.key].lossPercent}%</p>
          {results[check.key].rttMs && <p>Задержка, мс: {results[check.key].rttMs.min} / {results[check.key].rttMs.avg} / {results[check.key].rttMs.max} (мин. / сред. / макс.)</p>}
        </>}
      </div>
    </div>)}
    <p className="muted">Подсеть целиком не сканируется. Внешний IP может принадлежать NAT провайдера и не отвечать на ICMP. Отсутствие ответа не доказывает отключение объекта, а ответ не подтверждает работу SMB или 1С.</p>
  </section>;
}
