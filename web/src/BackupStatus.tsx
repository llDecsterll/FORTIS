import { useEffect, useState } from 'react';
import { api } from './api';

type Backup = { configured: boolean; storageStatus: string; jobStatus: string; automaticEnabled?: boolean; schedule?: string; lastSuccess?: { filename: string; sizeBytes: number; completedAt: string } | null; lastError?: string };
export function BackupStatus() {
  const [status, setStatus] = useState<Backup | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true); setError('');
    try { setStatus(await api.backupStatus()); } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);
  const labels: Record<string, string> = { connected: 'Подключено', not_mounted: 'Хранилище не смонтировано', unavailable: 'Недоступно', not_configured: 'Не настроено', running: 'Выполняется', failed: 'Ошибка', success: 'Завершено', unknown: 'Нет данных' };
  return <section className="card settings-section" aria-busy={busy}>
    <div className="settings-section-head"><div><h2>Резервные копии</h2><p>Состояние хранилища и последнего копирования.</p></div></div>
    {error && <p className="err" role="alert">{error}</p>}
    {!status && !error && <p role="status">Загрузка…</p>}
    {status && (!status.configured ? <p>Резервное копирование не настроено на сервере.</p> : <>
      <p>Хранилище: {labels[status.storageStatus] || status.storageStatus}</p>
      <p>Копирование: {labels[status.jobStatus] || status.jobStatus}</p>
      <p>Автоматическое копирование: {status.automaticEnabled ? status.schedule : 'Отключено'}</p>
      <p>Последняя копия: {status.lastSuccess ? `${status.lastSuccess.filename} · ${new Date(status.lastSuccess.completedAt).toLocaleString('ru-RU')}` : 'Нет данных'}</p>
      {status.lastError && <p className="err">{status.lastError}</p>}
    </>)}
    <button className="btn" disabled={busy} onClick={() => void load()}>Обновить состояние</button>
  </section>;
}
