import { FormEvent, useEffect, useState } from 'react';
import { api } from './api';
import './settings.css';
import { BackupStatus } from './BackupStatus';
import { ChannelStatus } from './ChannelStatus';

export function OperationsSettings({ section }: { section: 'channels' | 'backups' }) {
  const isChannels = section === 'channels';
  const [form, setForm] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const load = () => { setError(''); api.operations().then(setForm).catch(e => setError(e.message)); };
  useEffect(() => { if (isChannels) load(); }, [isChannels]);
  if (!isChannels) return <BackupStatus />;
  async function save(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(''); setMessage('');
    try {
      const {employeesMbps, sitesMbps, retentionDays, backupKind, backupHost, backupPath, backupUser} = form;
      const saved = await api.saveOperations({employeesMbps, sitesMbps, retentionDays, backupKind, backupHost, backupPath, backupUser});
      setForm(saved); setMessage(isChannels ? 'Настройки сохранены. Параметры мониторинга применятся при следующем замере.' : 'Черновик хранилища сохранён. Резервное копирование не включено.');
    } catch(e:any) { setError(e.message); } finally { setBusy(false); }
  }
  if (!form) return <section className="card settings-section" aria-labelledby="operations-title">
    <div className="settings-section-head"><span className="settings-section-index" aria-hidden="true">{isChannels ? '01' : '02'}</span><div><h2 id="operations-title">{isChannels ? 'Каналы и мониторинг' : 'Резервные копии'}</h2><p>{isChannels ? 'Параметры расчёта нагрузки и хранения истории.' : 'Параметры внешнего хранилища.'}</p></div></div>
    {error && <p className="err" role="alert">{error}</p>}
    <p className="settings-loading" role="status">{error ? 'Не удалось загрузить настройки.' : 'Загрузка настроек…'}</p>
    {error && <button className="btn" onClick={load}>Повторить загрузку</button>}
  </section>;
  return <form id="settings-operations-form" className="settings-operations" onSubmit={save} aria-label={isChannels ? 'Каналы и мониторинг' : 'Резервные копии'} aria-busy={busy}>
    {isChannels ? <section id="settings-monitoring" className="card settings-section" aria-labelledby="operations-title">
      <div className="settings-section-head"><span className="settings-section-index" aria-hidden="true">01</span><div><h2 id="operations-title">Каналы и мониторинг</h2><p>Скорости каналов и история измерений.</p></div><span className="settings-tag">Параметры расчёта</span></div>
      <ChannelStatus />
      <div className="settings-bandwidth-grid">
        {([['employeesMbps','Сотрудники','Канал сотрудников, Мбит/с'],['sitesMbps','Объекты','Канал объектов, Мбит/с']] as const).map(([key,title,label]) =>
          <div className="settings-bandwidth" key={key}><div className="settings-subhead"><span className="settings-small-dot" aria-hidden="true" /><h3>{title}</h3></div><label className="field"><span>{label}</span><input type="number" required min={0} max={100000} step="1" disabled={busy} value={form[key]} onChange={e=>setForm({...form,[key]:e.target.value === '' ? '' : Number(e.target.value)})}/></label><p className="settings-field-help">0 — использовать скорость сетевой карты</p></div>)}
      </div>
      <p className="settings-note">Скорость по тарифу используется только для расчёта загрузки, не ограничивает трафик. Для асимметричного канала укажите меньшую скорость: процент будет консервативным для обоих направлений.</p>
      <div className="settings-retention"><div><h3>История измерений</h3><p className="settings-field-help">Срок хранения относится к новым и ещё сохранившимся замерам. Ранее удалённая история не восстановится.</p></div><label className="field"><span>Хранение метрик, дней</span><input type="number" required min={2} max={30} step="1" disabled={busy} value={form.retentionDays} onChange={e=>setForm({...form,retentionDays:e.target.value === '' ? '' : Number(e.target.value)})}/></label></div>
      {error && <p className="err" role="alert">{error}</p>}
      {message && <p className="ok-msg" role="status">{message}</p>}
      <div className="settings-actions"><span className="settings-field-help">Изменения применятся при следующем замере.</span><button className="btn marking" disabled={busy}>{busy ? 'Сохранение…' : 'Сохранить параметры мониторинга'}</button></div>
    </section> : <section id="settings-backup" className="card settings-section" aria-labelledby="backup-title">
      <div className="settings-section-head"><span className="settings-section-index" aria-hidden="true">02</span><div><h2 id="backup-title">Резервные копии</h2><p>Выбор внешнего хранилища для следующего этапа настройки.</p></div><span className="settings-tag is-warning">Черновик</span></div>
      <div className="settings-warning" role="status"><strong>Резервное копирование не включено</strong><p>{form.backupMessage}</p><p>Сохранение адреса и папки не запускает копирование и не защищает от потери VPN-сервера.</p></div>
      <div className="form-grid">
        <label className="field"><span>Тип хранилища</span><select disabled={busy} value={form.backupKind} onChange={e=>setForm({...form,backupKind:e.target.value})}><option value="none">Не выбрано</option><option value="sftp">Сервер SFTP</option><option value="smb">NAS / SMB</option></select></label>
        {form.backupKind !== 'none' && <>
          <label className="field"><span>Адрес сервера хранилища</span><input required maxLength={253} disabled={busy} value={form.backupHost} placeholder="IP или DNS-имя" onChange={e=>setForm({...form,backupHost:e.target.value})}/></label>
          <label className="field"><span>Папка резервных копий</span><input required maxLength={512} disabled={busy} value={form.backupPath} onChange={e=>setForm({...form,backupPath:e.target.value})}/></label>
          <label className="field"><span>Пользователь хранилища</span><input required maxLength={128} disabled={busy} value={form.backupUser} onChange={e=>setForm({...form,backupUser:e.target.value})}/></label>
        </>}
      </div>
      <p className="settings-note">Не вводите пароли или ключи в эти поля. Подключение, учётные данные, шифрование и проверка восстановления — следующий этап после выбора хранилища.</p>
      {error && <p className="err" role="alert">{error}</p>}
      {message && <p className="ok-msg" role="status">{message}</p>}
      <div className="settings-actions"><span className="settings-field-help">Сохраняется только черновик: копирование пока не запускается.</span><button className="btn marking" disabled={busy}>{busy ? 'Сохранение…' : 'Сохранить черновик хранилища'}</button></div>
    </section>}
  </form>;
}
