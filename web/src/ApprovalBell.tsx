import {useEffect, useRef, useState} from 'react';
import {NavLink} from 'react-router-dom';
import {api} from './api';
import {startLiveRefresh} from '../public/live-sync.mjs';
import '../public/approval-center.css';

export function ApprovalBell() {
  const [count, setCount] = useState<number|null>(null);
  const [error, setError] = useState(false);
  const [ring, setRing] = useState(0);
  const previous = useRef<Set<string>|null>(null);
  useEffect(() => {
    let stopped = false, pending = false, queued = false;
    const load = async () => {
      if (stopped) return;
      if (pending) { queued = true; return; }
      pending = true;
      try {
        const result = await api.approvalSummary();
        if (stopped) return;
        if (!Number.isInteger(result.pending) || result.pending < 0 || !Array.isArray(result.pendingIds)) throw new Error('Некорректный счётчик заявок');
        const ids = new Set<string>(result.pendingIds);
        if (ids.size && (!previous.current || [...ids].some(id => !previous.current?.has(id)))) setRing(value => value + 1);
        previous.current = ids;
        setCount(result.pending); setError(false);
      } catch { if (!stopped) setError(true); }
      finally { pending = false; if (queued && !stopped) { queued = false; void load(); } }
    };
    const onChange = () => void load();
    const stop = startLiveRefresh(load);
    window.addEventListener('vpn:approvals-changed', onChange);
    return () => { stopped = true; stop(); window.removeEventListener('vpn:approvals-changed', onChange); };
  }, []);
  const label = error ? `Согласование: не удалось обновить уведомления${count === null ? '' : `, последнее число заявок ${count}`}` : count === null ? 'Согласование: загрузка уведомлений' : `Согласование: ожидают ${count}`;
  return <>
    <NavLink to="/approved?status=pending" className={`approval-bell${error ? ' stale' : ''}${count ? ' has-pending' : ''}`} aria-label={label} title={label}>
      <svg key={ring} className={ring ? 'approval-bell-ring' : ''} width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4M12 2V1" /></svg>
      <span className="approval-bell-count" aria-hidden="true">{error ? '!' : count === null ? '…' : count > 99 ? '99+' : count}</span>
    </NavLink>
    <span className="approval-sr-status" role="status">{label}</span>
  </>;
}
