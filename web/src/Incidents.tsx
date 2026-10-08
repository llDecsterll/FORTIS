import { useEffect, useState } from 'react';
import { api } from './api';
import { startLiveRefresh } from '../public/live-sync.mjs';
import { creationDateLabel } from '../public/creation-date.mjs';

export function Incidents() {
  const [status, setStatus] = useState<'current' | 'archived'>('current');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    const stop = startLiveRefresh(async () => {
      try {
        const result = await api.incidents(status, page);
        if (!active) return;
        if (page > 1 && !result.data.length) { setPage(page - 1); return; }
        setRows(result.data || []); setTotal(result.pagination.totalItems); setError('');
      } catch (e) { if (active) setError((e as Error).message); }
      finally { if (active) setLoading(false); }
    });
    return () => { active = false; stop(); };
  }, [status, page, revision]);
  async function archive(id: string) {
    setBusy(id); setError('');
    try { await api.archiveIncident(id, status === 'current'); setRevision(v => v + 1); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(''); }
  }
  function changeStatus(next: 'current' | 'archived') {
    setStatus(next); setPage(1); setRows([]); setTotal(0); setLoading(true); setError('');
  }
  return <>
    <div className="eyebrow">Безопасность</div><h1>Инциденты</h1>
    <p className="muted">События безопасности сотрудников и объектов. Архивирование сохраняет историю и не разблокирует VPN-ключ.</p>
    <div className="tabs" aria-label="Разделы инцидентов">
      <button className={status === 'current' ? 'on' : ''} aria-pressed={status === 'current'} disabled={!!busy} onClick={() => changeStatus('current')}>Текущие</button>
      <button className={status === 'archived' ? 'on' : ''} aria-pressed={status === 'archived'} disabled={!!busy} onClick={() => changeStatus('archived')}>Архивные</button>
    </div>
    {error && <div className="error-state" role="alert">{error}</div>}
    <div className="toolbar"><span className="muted">Записей: {total}</span><button type="button" className="btn ghost" disabled={!!busy || loading} onClick={() => setRevision(v => v + 1)}>Обновить</button></div>
    <div className="table-card" aria-busy={loading}>
      <table><thead><tr><th>Время</th><th>Сотрудник / объект</th><th>Инцидент</th><th>IP / провайдер</th><th>Геолокация / MAC</th><th>Результат отключения</th>{status === 'archived' && <th>Архивирование</th>}<th>Действие</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.id}>
          <td>{creationDateLabel(row.createdAt)}</td>
          <td>{row.subject || row.userName || 'Запись удалена'}<small className="muted">{row.subjectKind === 'object' ? 'Объект' : 'Сотрудник'}</small></td>
          <td>{row.title}<small className="muted">{row.code} · {({INFO:'Информация',WARNING:'Предупреждение',HIGH:'Высокий',CRITICAL:'Критический'} as Record<string,string>)[row.severity] || row.severity}</small>{row.details && <details><summary>Подробности</summary>{row.details}</details>}</td>
          <td><span className="mono">{row.externalIp || '—'}</span><small className="muted">{row.isp || '—'}</small></td>
          <td>{row.geo || '—'}<small className="mono muted">{row.mac || '—'}</small></td>
          <td><span className={`pill ${row.autoBlocked ? 'bad' : 'warn'}`}>{row.autoBlocked ? 'Отключение выполнено' : 'Отключение не подтверждено'}</span></td>
          {status === 'archived' && <td>{creationDateLabel(row.archivedAt)}<small className="muted">{row.archivedBy || '—'}</small></td>}
          <td><button disabled={!!busy} onClick={() => archive(row.id)}>{busy === row.id ? 'Сохраняем…' : status === 'current' ? 'В архив' : 'Вернуть'}</button></td>
        </tr>)}</tbody>
      </table>
      {!rows.length && !error && <div className="empty" role="status">{loading ? 'Загружаем инциденты…' : status === 'current' ? 'Текущих инцидентов нет' : 'Архив пуст'}</div>}
    </div>
    {total > 50 && <div className="toolbar" aria-label="Страницы инцидентов">
      <button disabled={page <= 1 || !!busy || loading} onClick={() => { setLoading(true); setPage(page - 1); }}>Назад</button>
      <span>Страница {page} из {Math.ceil(total / 50)}</span>
      <button disabled={page * 50 >= total || !!busy || loading} onClick={() => { setLoading(true); setPage(page + 1); }}>Далее</button>
    </div>}
  </>;
}
