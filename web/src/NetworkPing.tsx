import { FormEvent, useState } from 'react';
import { api } from './api';

type Result = {
  ip: string; sent: number; received: number; lossPercent: number; reachable: boolean;
  rttMs: { min: number; avg: number; max: number } | null; output: string;
};

export function NetworkPing() {
  const [ip, setIp] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  async function run(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(''); setResult(null);
    try { setResult(await api.pingNetwork(ip.trim())); }
    catch (err: any) { setError(err.message || 'Не удалось выполнить проверку'); }
    finally { setBusy(false); }
  }
  return <section className="card" aria-labelledby="network-ping-heading">
    <h2 id="network-ping-heading">Пинг IP-адреса</h2>
    <p className="muted">Проверка с VPN-сервера: 3 пакета, до 7 секунд. Повторный запуск — через 10 секунд. Маршруты и доступы не изменяются.</p>
    <form className="form-grid" onSubmit={run} aria-label="Проверка IP-адреса">
      <label htmlFor="network-ping-ip">IP-адрес<input id="network-ping-ip" required maxLength={45} placeholder="Например, 192.168.3.6" value={ip} disabled={busy} onChange={e => setIp(e.target.value)} aria-describedby="network-ping-help" /></label>
      <div className="h-row"><button className="btn" disabled={busy || !ip.trim()}>{busy ? 'Проверяем…' : 'Пинг'}</button></div>
    </form>
    <p id="network-ping-help" className="muted">Введите один IPv4-адрес вручную, без порта и маски. Ответ ICMP не подтверждает работу SMB или 1С; отсутствие ответа может быть связано с запретом ICMP.</p>
    {error && <p className="error-state" role="alert">{error}</p>}
    <div role="status" aria-live="polite" aria-busy={busy}>
      {result && <>
        <p><strong className="mono">{result.ip}</strong> · {result.reachable ? 'Есть ответ' : 'Нет ответа'} · Отправлено: {result.sent} · Получено: {result.received} · Потери: {result.lossPercent}%</p>
        {result.rttMs && <p>Задержка, мс: минимум {result.rttMs.min} · средняя {result.rttMs.avg} · максимум {result.rttMs.max}</p>}
        <details><summary>Вывод ping</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{result.output}</pre></details>
      </>}
    </div>
  </section>;
}
