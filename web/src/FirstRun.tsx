import { FormEvent, ReactNode, useEffect, useState } from 'react';
import { api, clearToken, getToken, setToken } from './api';
import { BrandMark } from './BrandMark';
import './first-run.css';

type Transaction = { status: string; expiresAt?: number; error?: string };
type Status = { completed: boolean; adminCreated: boolean; platform: string; interfacesLocked: boolean; serverReady: boolean; networkTransaction: Transaction };
type Interface = { name: string; subnet: string; port: number; uplink: string; endpoint: string };
type Connection = Interface & { role: '' | 'later' | 'employees' | 'routers' | 'custom'; customName: string };
type Config = Record<string, Connection>;
type Host = { id: string; name: string; mac: string; up: boolean; mtu: number; kind: string; method: string; editable: boolean; selectable: boolean; gateway: string; dns: string[]; addresses: { address: string; prefix: number; family: number }[] };
type HostPlan = { purpose?: string; id: string; originalName: string; name: string; mode: 'keep' | 'dhcp' | 'static'; address: string; gateway: string; dns: string[] };
type Inventory = { interfaces: Host[]; plan: HostPlan[]; transaction: Transaction; manager: string; message: string; lockedUplinks: string[] };
type Report = { ready: boolean; serverReady?: boolean; error?: string; notice: string; checks: { name: string; ok: boolean; detail: string }[]; openPorts?: { available: boolean; error: string; ports: { protocol: string; address: string; port: number }[] } };
type AdForm = { enabled: boolean; id: string; host: string; port: number; useSsl: boolean; bindDn: string; password: string; baseDn: string };
const initialAd: AdForm = { enabled: false, id: '', host: '', port: 636, useSsl: true, bindDn: '', password: '', baseDn: '' };
async function setup<T>(path: string, body?: unknown, method = 'POST'): Promise<T> {
  let response: Response;
  try {
    response = await fetch('/api/setup/' + path, { method: body === undefined ? 'GET' : method,
      headers: { 'Content-Type': 'application/json',  },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  } catch { throw new Error('Нет связи с сервером. После смены IP откройте панель по новому адресу или дождитесь отката сети.'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) clearToken();
    const detail = data.error?.message || data.detail;
    throw new Error(Array.isArray(detail) ? detail.map((d: {msg: string}) => d.msg.replace(/^Value error, /, '')).join('; ') : detail || 'Сервер не ответил. Проверьте серверную часть.');
  }
  return data;
}

export function FirstRun({ children, settingsMode = false }: { children?: ReactNode; settingsMode?: boolean }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [admin, setAdmin] = useState({ fullName: '', email: '', password: '' });
  const [repeat, setRepeat] = useState('');
  const [challenge, setChallenge] = useState<{challenge: string; qr?: string; secret?: string} | null>(null);
  const [code, setCode] = useState('');
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [hosts, setHosts] = useState<HostPlan[]>([]);
  const [transaction, setTransaction] = useState<Transaction>({ status: 'none' });
  const [now, setNow] = useState(Date.now());
  const [ad, setAd] = useState<AdForm>(initialAd);
  const [adCheck, setAdCheck] = useState('');
  const [connections, setConnections] = useState<Record<string, Connection>>({});
  const [networkMessage, setNetworkMessage] = useState('');
  const [report, setReport] = useState<Report | null>(null);
  const pending = transaction.status === 'pending' || transaction.status === 'applying';
  const cards = inventory?.interfaces.filter(h => h.selectable) || [];
  const systemInterfaces = inventory?.interfaces.filter(h => !h.selectable) || [];
  const noConnection = !Object.values(connections).some(c => c.role && c.role !== 'later');
  const unassigned = cards.some(h => !connections[h.id]?.role);

  async function loadNetwork(reset = false, saved: Config = {}) {
    const data = await setup<Inventory>('network');
    setInventory(data); setTransaction(data.transaction);
    const plans = data.interfaces.filter(h => h.selectable).map(host => {
      const saved = data.plan.find(p => p.id === host.id && p.originalName === host.name);
      const locked = data.lockedUplinks?.includes(host.name);
      if (locked) return { id: host.id, originalName: host.name, name: host.name, mode: 'keep' as const, address: '', gateway: '', dns: [] };
      const ip = host.addresses.find(a => a.family === 4);
      return saved || { id: host.id, originalName: host.name, name: host.name, mode: 'keep' as const,
        address: ip ? `${ip.address}/${ip.prefix}` : '', gateway: host.gateway || '', dns: host.dns || [] };
    });
    setHosts(previous => reset || !previous.length ? plans : plans.map(p => previous.find(h => h.id === p.id) || p));
    setConnections(previous => {
      const next: Record<string, Connection> = {};
      const selectable = data.interfaces.filter(h => h.selectable);
      selectable.forEach((host, index) => {
        const old = Object.entries(saved).find(([, c]) => c.uplink === host.name || c.uplink === plans.find(p => p.id === host.id)?.name);
        const value = old ? { ...old[1], role: old[1].role || (old[0] === 'employees' ? 'employees' : old[0] === 'sites' ? 'routers' : 'custom'), customName: old[1].customName || '' } as Connection : null;
        next[host.id] = value || (!reset && previous[host.id]) || { role: data.plan.find(p => p.id === host.id)?.purpose === 'later' ? 'later' : index === 0 && !Object.keys(saved).length ? 'employees' : '', customName: '',
          name: index === 0 ? 'wg-employees' : `wg-${index + 1}`, subnet: `10.${80 + index}.0.0/24`, port: 51820 + index,
          uplink: host.name, endpoint: host.addresses.find(a => a.family === 4)?.address || '' };
      });
      return next;
    });
    return data;
  }
  async function loadAd() {
    const saved = await setup<{ sources: Omit<AdForm, 'enabled' | 'password'>[] }>('ad');
    if (saved.sources[0]) setAd({ ...initialAd, ...saved.sources[0], enabled: true, password: '' });
  }
  async function resume(state: Status) {
    const saved = await setup<Config>('interfaces');
    const net = await loadNetwork(true, saved);
    if (state.serverReady) { setStep(3); await loadAd(); }
    else if (Object.keys(saved).length && !['pending', 'applying', 'rollback_failed'].includes(net.transaction.status) && (!net.plan.some(p => p.mode !== 'keep' || p.name !== p.originalName) || net.transaction.status === 'confirmed')) {
      setStep(2); setReport(await setup<Report>('checks'));
    } else setStep(1);
  }
  async function initialize() {
    setError('');
    try {
      const state = await setup<Status>('status'); setStatus(state);
      if (settingsMode) {
        const saved = await setup<Config>('interfaces'); await loadNetwork(true, saved); setStep(1);
      } else if (!state.completed && state.adminCreated && getToken()) {
        try { await resume(state); } catch (e) { setStep(0); setError((e as Error).message); }
      }
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { void initialize(); }, []);
  useEffect(() => {
    if (!pending) return;
    let stopped = false;
    const interval = window.setInterval(() => {
      setNow(Date.now());
      void setup<Transaction>('network/transaction').then(value => { if (!stopped) setTransaction(value); }).catch(() => {});
    }, 2000);
    return () => { stopped = true; window.clearInterval(interval); };
  }, [pending]);
  async function action(work: () => Promise<void>) {
    setBusy(true); setError('');
    try { await work(); } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  async function administrator(event: FormEvent) {
    event.preventDefault();
    await action(async () => {
      if (!status?.adminCreated) {
        if (admin.password !== repeat) throw new Error('Пароли не совпадают');
        const result = await setup<{token: string}>('admin', admin);
        setToken(result.token); setAdmin({ fullName: '', email: '', password: '' }); setRepeat('');
        setStatus(current => current ? { ...current, adminCreated: true } : current);
        setStep(1); await loadNetwork(true);
      } else {
        const result: Awaited<ReturnType<typeof api.login>> = challenge ? await api.confirmTotp(challenge.challenge, code) : await api.login(admin.email, admin.password);
        if (result.blocked) throw new Error('Учётная запись заблокирована');
        if (result.totpRequired || result.totpSetup) {
          setChallenge({ challenge: result.challenge!, qr: result.qr, secret: result.secret }); return;
        }
        setToken(result.token); setChallenge(null); setAdmin({ fullName: '', email: '', password: '' });
        const state = await setup<Status>('status'); setStatus(state); await resume(state);
      }
    });
  }
  function changeHost(id: string, patch: Partial<HostPlan>) {
    const old = hosts.find(h => h.id === id);
    setHosts(values => values.map(h => h.id === id ? { ...h, ...patch } : h));
    if (patch.address !== undefined && old) setConnections(values => {
      const connection = values[id];
      return connection?.endpoint === old.address.split('/')[0] ? { ...values, [id]: { ...connection, endpoint: patch.address!.split('/')[0] } } : values;
    });
    if (patch.name !== undefined && old) setConnections(values => ({ ...values, [id]: { ...values[id], uplink: patch.name! } }));
  }
  async function showChecks() {
    if (settingsMode) {
      const result = await setup<Report>('network/activate', {}); setReport(result);
      if (!result.ready) throw new Error(result.error || 'Новые подключения не прошли проверку');
      setNetworkMessage('Назначения карт сохранены. Новые подключения запущены и проверены.');
      const saved = await setup<Config>('interfaces'); await loadNetwork(true, saved);
    } else { setStep(2); setReport(await setup<Report>('checks')); }
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    await action(async () => {
      if (noConnection || unassigned) throw new Error('Укажите назначение каждой карты или выберите «Настроить позже»');
      const active = Object.values(connections).filter(c => c.role && c.role !== 'later');
      const selected = new Set(active.map(c => c.uplink));
      const plan = hosts.map(h => ({ ...(selected.has(h.name) ? h : { ...h, mode: 'keep', name: h.originalName }), dns: h.dns.map(v => v.trim()).filter(Boolean), purpose: connections[h.id]?.role || 'later' }));
      await setup('network', { hosts: { interfaces: plan }, connections: active }, 'PUT');
      const result = await setup<Transaction>('network/apply', {});
      setTransaction(result); setNow(Date.now());
      if (result.status === 'unchanged' || result.status === 'confirmed') await showChecks();
    });
  }
  async function confirmNetwork() {
    await action(async () => { setTransaction(await setup<Transaction>('network/confirm', {})); await showChecks(); });
  }
  async function launch() {
    await action(async () => {
      const result = await setup<Report>('start', {}); setReport(result);
      const state = await setup<Status>('status'); setStatus(state);
      if (result.serverReady && result.ready) { setStep(3); await loadAd(); }
      else if (result.error) setError(result.error);
    });
  }
  async function finish(useAd: boolean) {
    await action(async () => {
      await setup('finish', useAd ? { ...ad, enabled: true } : { enabled: false });
      clearToken(); window.location.assign('/login');
    });
  }
  if (status?.completed && !settingsMode) return <>{children}</>;
  const steps = ['Администратор', 'Сетевые интерфейсы', 'Сервер и открытые порты', 'Active Directory'];
  const remaining = transaction.expiresAt ? Math.max(0, Math.floor(transaction.expiresAt - now / 1000 - 30)) : 0;
  const Root = settingsMode ? 'div' : 'main';
  return <Root className={`first-run${settingsMode ? " setup-settings-mode" : ""}`}>
    <aside className="setup-sidebar">
      <div className="setup-brand"><BrandMark /><span>FORTIS</span></div>
      <p className="setup-eyebrow">Первый запуск</p><h1>Подготовьте сервер<br />к подключению</h1>
      <p className="setup-description">Создайте администратора, настройте сетевые карты, проверьте сервер и подключите AD при необходимости.</p>
      <ol className="setup-steps">{steps.map((label, index) => <li key={label} aria-current={step === index ? 'step' : undefined} className={index === step ? 'current' : index < step ? 'done' : ''}><span>{index < step ? '✓' : index + 1}</span>{label}</li>)}</ol>
      <p className="setup-footnote">Настройки сохраняются на сервере. После перезапуска можно продолжить с текущего шага.</p>
    </aside>
    <section className="setup-content" aria-busy={busy}>
      {!status ? <div className="setup-panel"><h2>Подключение к серверу</h2><p>Проверяем состояние первичной настройки…</p>{error && <div role="alert" className="setup-error">{error}</div>}<button onClick={() => void initialize()}>Повторить проверку</button></div> : <>
        {!settingsMode && <div className="setup-heading"><span>Шаг {step + 1} из 4</span><span>{status.platform}</span></div>}
        {error && <div role="alert" className="setup-error">{error}</div>}
        {step === 0 && <form className="setup-panel" onSubmit={administrator}>
          <h2>{status.adminCreated ? 'Продолжить настройку' : 'Создайте администратора'}</h2>
          <p>{status.adminCreated ? 'Войдите под созданным администратором.' : 'Эта учётная запись будет управлять пользователями, подключениями и настройками сервера.'}</p>
          {challenge ? <>
            <h3>{challenge.qr ? 'Подключите приложение 2FA' : 'Подтвердите вход'}</h3>
            {challenge.qr && <><img className="setup-qr" src={challenge.qr} alt="QR-код для приложения двухфакторной аутентификации" /><p>Добавьте QR-код в приложение-аутентификатор.</p><code>{challenge.secret}</code></>}
            <label>Код из приложения<input required inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={e => setCode(e.target.value)} /></label>
          </> : <>
            {!status.adminCreated && <label>Имя администратора<input required minLength={2} maxLength={120} autoComplete="name" value={admin.fullName} onChange={e => setAdmin({ ...admin, fullName: e.target.value })} /></label>}
            <label>Email<input required type="email" autoComplete="username" value={admin.email} onChange={e => setAdmin({ ...admin, email: e.target.value })} /></label>
            <label>Пароль<input required type="password" minLength={status.adminCreated ? 1 : 12} maxLength={72} autoComplete={status.adminCreated ? 'current-password' : 'new-password'} value={admin.password} onChange={e => setAdmin({ ...admin, password: e.target.value })} />{!status.adminCreated && <small>Минимум 12 символов. Сохраните пароль для последующего входа.</small>}</label>
            {!status.adminCreated && <label>Повторите пароль<input required type="password" autoComplete="new-password" value={repeat} onChange={e => setRepeat(e.target.value)} /></label>}
          </>}
          <button disabled={busy}>{busy ? 'Сохраняем…' : status.adminCreated ? 'Продолжить' : 'Создать администратора'}</button>
        </form>}
        {step === 1 && <form onSubmit={save} className="setup-panel setup-wide">
          <div className="setup-section-title"><div><h2>Сетевые интерфейсы</h2><p>Все карты сервера, текущие IP-адреса и назначение каждой карты.</p></div><button type="button" className="setup-secondary" disabled={busy || pending} onClick={() => void action(async () => { await loadNetwork(); })}>Обновить список</button></div>
          {inventory?.message && <p className="setup-notice">{inventory.message}</p>}
          {!inventory && <p role="status">Обнаруживаем сетевые интерфейсы…</p>}
          {inventory && !cards.length && <div role="alert" className="setup-error">Сетевые карты не обнаружены. Подключите карту и обновите список.</div>}
          {cards.length === 1 && <p className="setup-notice">На сервере одна сетевая карта. Будет создано одно подключение с выбранным назначением.</p>}
          {cards.length > 1 && <p className="setup-notice">Назначьте каждой карте роль или выберите «Настроить позже». Одна карта создаёт одно подключение.</p>}
          {networkMessage && <p className="setup-notice" role="status">{networkMessage}</p>}
          {transaction.error && <div role="alert" className="setup-error">{transaction.error}</div>}
          {pending && <div className="setup-network-confirm" role="status"><strong>Проверьте связь после изменения сети</strong><p>Откройте панель по новому IP, если он изменился, и подтвердите, что сервер доступен. Без подтверждения Netplan вернёт предыдущие настройки. Осталось около {remaining} сек.</p><div className="setup-actions"><button type="button" disabled={busy || remaining === 0} onClick={() => void confirmNetwork()}>Связь сохранена — подтвердить</button><button type="button" className="setup-secondary" disabled={busy} onClick={() => void action(async () => { setTransaction(await setup<Transaction>('network/cancel', {})); await loadNetwork(true, await setup<Config>('interfaces')); })}>Отменить изменения сети</button></div></div>}
          <div className="setup-hosts">{cards.map(host => {
            const plan = hosts.find(p => p.id === host.id);
            const connection = connections[host.id];
            if (!plan || !connection) return null;
            const assigned = !!connection.role && connection.role !== 'later';
            const locked = inventory?.lockedUplinks?.includes(host.name) || inventory?.lockedUplinks?.includes(plan.name);
            return <fieldset key={host.id} disabled={busy || pending || locked} className="setup-host-card"><legend>{host.name}</legend>
              <div className="setup-host-top"><span className={host.up ? 'setup-link-up' : 'setup-link-down'}>{host.up ? 'Активен' : 'Нет связи'}</span><span>MAC {host.mac || 'не определён'} · MTU {host.mtu}</span>{locked && <span>Подключение запущено</span>}</div>
              <div className="setup-current-ips"><span>Текущие IP</span>{host.addresses.length ? host.addresses.map(ip => <code key={ip.address}>{ip.address}/{ip.prefix}</code>) : <p>IP-адрес пока не назначен</p>}</div>
              <label>Назначение карты<select required value={connection.role} onChange={e => {
                const role = e.target.value as Connection['role'];
                setConnections(values => ({ ...values, [host.id]: { ...connection, role,
                  name: role === 'employees' ? 'wg-employees' : role === 'routers' ? 'wg-routers' : connection.name } }));
                if (role === 'later') changeHost(host.id, { name: host.name, mode: 'keep' });
              }}><option value="" disabled>Выберите назначение</option><option value="employees" disabled={Object.entries(connections).some(([id, c]) => id !== host.id && c.role === 'employees')}>Сотрудники</option><option value="routers" disabled={Object.entries(connections).some(([id, c]) => id !== host.id && c.role === 'routers')}>Роутеры</option><option value="custom">Указать своё</option><option value="later">Настроить позже</option></select></label>
              {connection.role === 'custom' && <label>Своё назначение<input required maxLength={80} placeholder="Например, подрядчики" value={connection.customName} onChange={e => setConnections(values => ({ ...values, [host.id]: { ...connection, customName: e.target.value } }))} /></label>}
              {assigned && <>
                <div className="setup-host-fields"><label>Имя интерфейса в системе<input maxLength={15} pattern="[a-zA-Z][a-zA-Z0-9_.-]{0,14}" required disabled={!host.editable} value={plan.name} onChange={e => changeHost(host.id, { name: e.target.value })} /></label>
                  <label>Получение IPv4<select disabled={!host.editable} value={plan.mode} onChange={e => changeHost(host.id, { mode: e.target.value as HostPlan['mode'] })}><option value="keep">Оставить текущие {host.method === 'dhcp' ? '(DHCP)' : host.method === 'static' ? '(вручную)' : ''}</option><option value="dhcp">Автоматически — DHCP</option><option value="static">Указать IP вручную</option></select></label>
                  {plan.mode === 'static' && <><label>IP-адрес с маской<input required placeholder="192.168.1.10/24" value={plan.address} onChange={e => changeHost(host.id, { address: e.target.value })} /></label><label>Шлюз IPv4<input placeholder="192.168.1.1" value={plan.gateway} onChange={e => changeHost(host.id, { gateway: e.target.value })} /></label><label className="setup-full-field">DNS-серверы через запятую<input placeholder="192.168.1.1, 1.1.1.1" value={plan.dns.join(',')} onChange={e => changeHost(host.id, { dns: e.target.value.split(',') })} /><small>Необязательно. Адреса карты и клиентов VPN задаются отдельно.</small></label></>}
                </div>
                {!host.editable && <small>Текущие параметры можно использовать для подключения. Изменение системного IP и имени этой карты через мастер недоступно.</small>}
                <h3 className="setup-subtitle">Параметры подключения клиентов</h3>
                <div className="setup-host-fields">{([['name', 'Имя VPN-интерфейса', 'wg-employees'], ['subnet', 'Подсеть для клиентов', '10.80.0.0/24'], ['port', 'UDP-порт подключения', '51820'], ['endpoint', 'IP или DNS-имя для клиентов', 'vpn.example.ru']] as const).map(([field, label, placeholder]) => <label key={field}>{label}<input required type={field === 'port' ? 'number' : 'text'} min={field === 'port' ? 1 : undefined} max={field === 'port' ? 65535 : undefined} placeholder={placeholder} value={connection[field]} onChange={e => setConnections(values => ({ ...values, [host.id]: { ...connection, [field]: field === 'port' ? Number(e.target.value) : e.target.value } }))} /></label>)}</div>
                <small>Подсеть клиентов и UDP-порт должны быть отдельными для каждого подключения.</small>
              </>}
              {connection.role === 'later' && <p className="setup-later-note">Карта сохранит текущие настройки. Подключение для неё можно создать позже в разделе «Настройки → Сетевые интерфейсы».</p>}
            </fieldset>;
          })}</div>
          {!!systemInterfaces.length && <details className="setup-system-interfaces"><summary>Служебные и виртуальные интерфейсы ({systemInterfaces.length})</summary>{systemInterfaces.map(host => <div key={host.id}><strong>{host.name}</strong><span>{host.up ? 'Активен' : 'Не активен'}</span><code>{host.addresses.map(a => `${a.address}/${a.prefix}`).join(', ') || 'Без IP-адреса'}</code></div>)}</details>}
          <div className="setup-actions"><button disabled={busy || pending || noConnection || unassigned || !inventory}>{busy ? 'Применяем…' : settingsMode ? 'Сохранить и запустить новые подключения' : 'Сохранить сеть и перейти к проверке'}</button></div>
        </form>}
        {step === 2 && <div className="setup-panel setup-wide">
          <h2>Сервер и открытые порты</h2><p>Проверим сетевые карты, подсети и занятость портов. Затем создадим VPN-интерфейсы и проверим, что сервер слушает указанные UDP-порты и разрешает их в firewall.</p>
          <div className="setup-checks" aria-live="polite">{report?.checks.map(check => <div key={check.name} className="setup-check"><span className={check.ok ? 'check-ok' : 'check-fail'}>{check.ok ? '✓' : '!'}</span><div><strong>{check.name}</strong><p>{check.detail}</p></div><span>{check.ok ? 'Готово' : 'Требует внимания'}</span></div>)}</div>
          {report?.openPorts && <div className="setup-ports"><h3>Порты, которые слушает сервер</h3>{report.openPorts.available ? <div className="setup-table-wrap"><table><thead><tr><th>Протокол</th><th>Адрес</th><th>Порт</th></tr></thead><tbody>{report.openPorts.ports.map(p => <tr key={`${p.protocol}:${p.address}:${p.port}`}><td>{p.protocol}</td><td>{p.address}</td><td>{p.port}</td></tr>)}</tbody></table>{!report.openPorts.ports.length && <p>Слушающие порты не найдены.</p>}</div> : <p>{report.openPorts.error}</p>}</div>}
          {report && <p className="setup-notice">{report.notice}</p>}
          {report && !report.ready && <p className="setup-notice">Устраните отмеченные проблемы и повторите проверку. Настройки уже сохранены.</p>}
          <div className="setup-actions"><button className="setup-secondary" disabled={busy || status.interfacesLocked} onClick={() => setStep(1)}>Вернуться к сети</button><button className="setup-secondary" disabled={busy} onClick={() => void action(async () => setReport(await setup<Report>('checks')))}>Проверить снова</button><button disabled={busy || !report?.ready} onClick={() => void launch()}>{busy ? 'Проверяем и запускаем…' : 'Запустить и проверить порты'}</button></div>
        </div>}
        {step === 3 && <form className="setup-panel setup-wide" onSubmit={e => { e.preventDefault(); void finish(true); }}>
          <h2>Active Directory</h2><p>Сервер запущен и проверен. Подключите корпоративный каталог для синхронизации пользователей или завершите настройку без AD.</p>
          <fieldset disabled={busy}><legend>Подключение каталога</legend><label className="setup-checkbox"><input type="checkbox" checked={ad.enabled} onChange={e => { setAd({ ...ad, enabled: e.target.checked }); setAdCheck(''); }} />Использовать Active Directory</label>
          {ad.enabled && <div className="setup-host-fields"><label>Сервер AD<input required placeholder="dc.example.ru" value={ad.host} onChange={e => { setAd({ ...ad, host: e.target.value }); setAdCheck(''); }} /></label><label>Порт<input type="number" min={1} max={65535} required value={ad.port} onChange={e => { setAd({ ...ad, port: Number(e.target.value) }); setAdCheck(''); }} /></label><label className="setup-checkbox setup-full-field"><input type="checkbox" checked={ad.useSsl} onChange={e => { setAd({ ...ad, useSsl: e.target.checked, port: e.target.checked ? 636 : 389 }); setAdCheck(''); }} />LDAPS</label><label>Учётная запись каталога<input required autoComplete="off" placeholder="user@example.ru" value={ad.bindDn} onChange={e => { setAd({ ...ad, bindDn: e.target.value }); setAdCheck(''); }} /></label><label>Пароль<input type="password" required autoComplete="new-password" value={ad.password} onChange={e => { setAd({ ...ad, password: e.target.value }); setAdCheck(''); }} /></label><label className="setup-full-field">Base DN<input required placeholder="OU=Employees,DC=example,DC=ru" value={ad.baseDn} onChange={e => { setAd({ ...ad, baseDn: e.target.value }); setAdCheck(''); }} /></label></div>}
          </fieldset>
          {adCheck && <p className="setup-notice" role="status">{adCheck}</p>}
          <div className="setup-actions"><button type="button" className="setup-secondary" disabled={busy} onClick={() => { setStep(2); void action(async () => setReport(await setup<Report>('checks'))); }}>Вернуться к проверке</button>{ad.enabled && <><button type="button" className="setup-secondary" disabled={busy} onClick={() => void action(async () => { const result = await setup<{detail: string}>('ad/check', ad); setAdCheck(result.detail); })}>Проверить AD</button><button disabled={busy}>{busy ? 'Проверяем…' : 'Подключить AD и завершить'}</button></>}<button type="button" className={ad.enabled ? 'setup-secondary' : ''} disabled={busy} onClick={() => void finish(false)}>Пропустить AD и завершить</button></div>
        </form>}
      </>}
    </section>
  </Root>;
}
