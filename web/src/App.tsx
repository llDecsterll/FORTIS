import { FormEvent, ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import { NetworkChannels } from './NetworkChannels';
import { lastOnlineLabel } from './last-online.mjs';
import { ServerLoad } from './ServerLoad';
import { TrafficSummary } from './TrafficSummary';
import { ConnectionStates, connectionLabels } from './ConnectionStates';
import { ResourceDialog } from './ResourceDialog';
import { SiteLinks } from './SiteLinks';
import { NetworkPing } from './NetworkPing';
import { SitePing } from './SitePing';
import { DeleteNetworkDialog } from './DeleteNetworkDialog';
import { startLiveRefresh } from '../public/live-sync.mjs';
import { creationDateLabel } from '../public/creation-date.mjs';
import { ownerLabel } from '../public/owner-label.mjs';
import { matchesName } from '../public/name-search.mjs';
import { OperationsSettings } from './OperationsSettings';
import { FirstRun } from './FirstRun';
import { AdSettings } from './AdSettings';
import { BrandMark } from './BrandMark';
import { ApprovalBell } from './ApprovalBell';
import { Incidents } from './Incidents';

function useLiveData(load: () => Promise<unknown>, dependencies: unknown[] = []) {
  const current = useRef(load);
  current.current = load;
  useEffect(() => startLiveRefresh(() => current.current()), dependencies);
}
import { getDocument, GlobalWorkerOptions } from "pdfjs-dist";
import pdfWorker from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, clearToken, getToken, saveTextFile, setToken } from "./api";

const nav = [
  ["/", "Обзор сети"],
  ["/users", "Сотрудники"],
  ["/sites", "Объекты"],
  ["/connections", "Инциденты"],
  ["/networks", "Сети и ресурсы"],
  ["/approved", "Согласование"],
  ["/audit", "Журнал событий"],
  ["/settings", "Настройки"],
];

function initials(name: string) {
  return (name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase();
}

function NavIcon({ to }: { to: string }) {
  const p = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (to === "/") return <svg {...p}><path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" /></svg>;
  if (to === "/users") return <svg {...p}><path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2" /><circle cx="9.5" cy="7" r="3.5" /><path d="M20 8v6M17 11h6" /></svg>;
  if (to === "/connections") return <svg {...p}><path d="M5 12.5h3l2-6 3 12 2-6h4" /></svg>;
  if (to === "/sites") return <svg {...p}><path d="M3 21h18M5 21V8l7-5 7 5v13M9 21v-6h6v6" /></svg>;
  if (to === "/networks") return <svg {...p}><circle cx="12" cy="12" r="3" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" /></svg>;
  if (to === "/requests") return <svg {...p}><path d="M8 7h11M8 12h11M8 17h7" /><circle cx="4" cy="7" r="1" /><circle cx="4" cy="12" r="1" /><circle cx="4" cy="17" r="1" /></svg>;
  if (to === "/audit") return <svg {...p}><path d="M12 8v4l2.5 1.5" /><circle cx="12" cy="12" r="9" /></svg>;
  if (to === "/approved") return <svg {...p}><rect x="4" y="3" width="16" height="18" rx="3" /><path d="m8 12 3 3 5-6" /></svg>;
  return <svg {...p} aria-hidden="true"><path d="M9.5 3h5l.6 2.5 1.4.8 2.5-.7 2.5 4.3-1.9 1.8v1.6l1.9 1.8-2.5 4.3-2.5-.7-1.4.8-.6 2.5h-5l-.6-2.5-1.4-.8-2.5.7L2.5 15.1l1.9-1.8v-1.6L2.5 9.9 5 5.6l2.5.7 1.4-.8z" /><circle cx="12" cy="12.5" r="3" /></svg>;
}

function pill(status: string) {
  const s = (status || "").toUpperCase();
  if (["ONLINE", "ISSUED", "APPROVED_SB", "OK"].includes(s)) return "pill ok";
  if (["BLOCKED", "REVOKED", "REJECTED", "CRITICAL"].includes(s)) return "pill bad";
  if (["PENDING", "PENDING_APPROVAL", "WARNING", "EXPIRED", "OFFLINE"].includes(s)) return "pill warn";
  return "pill info";
}

function keyReleased(approval?: string) {
  return !approval || approval === "APPROVED_SB" || approval === "ISSUED";
}

function accountLabel(u: { blocked?: boolean; suspended?: boolean; isActive?: boolean; status?: string; approval?: string }) {
  if (u.approval === "PENDING_APPROVAL") return { text: "На согласовании", pill: "PENDING_APPROVAL" };
  if (u.approval === "REJECTED") return { text: "Отклонено СБ", pill: "REJECTED" };
  if (u.status === "EXPIRED") return { text: "Срок истёк", pill: "EXPIRED" };
  if (u.blocked || u.isActive === false) return { text: "Заблокирован", pill: "BLOCKED" };
  if (u.suspended) return { text: "Приостановлен", pill: "PENDING" };
  return { text: "Активен", pill: "OK" };
}

function untilLabel(value?: string | null) {
  if (!value) return "Бессрочно";
  return creationDateLabel(value);
}


function accessTone(value?: string | null) {
  if (!value) return { text: "Бессрочно", pill: "OK" };
  const left = new Date(value).getTime() - Date.now();
  const days = Math.ceil(left / 86400000);
  if (left <= 0) return { text: "Истёк", pill: "BLOCKED" };
  if (days <= 1) return { text: "Меньше суток", pill: "BLOCKED" };
  if (days <= 7) return { text: `${days} дн.`, pill: "WARNING" };
  return { text: `${days} дн.`, pill: "OK" };
}

function deviceKindLabel(type?: string) {
  const map: Record<string, string> = {
    LAPTOP: "Ноутбук",
    DESKTOP: "Компьютер",
    PHONE: "Телефон",
    ROUTER: "Маршрутизатор",
    SERVER: "Сервер",
    CAMERA: "Камера",
    CONTROLLER: "Контроллер",
    OTHER: "Другое",
  };
  return map[(type || "").toUpperCase()] || "";
}

function publicIp(endpoint?: string) {
  const ep = (endpoint || "").trim();
  if (!ep || ep === "(none)" || ep === "none") return "";
  return ep.replace(/^\[|\]$/g, "").replace(/:\d+$/, "");
}

const PLACE_RU: Record<string, string> = {
  russia: "Россия",
  moscow: "Москва",
  "saint petersburg": "Санкт-Петербург",
  "st. petersburg": "Санкт-Петербург",
  "st petersburg": "Санкт-Петербург",
  "nizhny novgorod": "Нижний Новгород",
  kazan: "Казань",
  novosibirsk: "Новосибирск",
  yekaterinburg: "Екатеринбург",
  "rostov-on-don": "Ростов-на-Дону",
  krasnodar: "Краснодар",
  samara: "Самара",
  ufa: "Уфа",
  chelyabinsk: "Челябинск",
  perm: "Пермь",
  voronezh: "Воронеж",
  volgograd: "Волгоград",
  krasnoyarsk: "Красноярск",
  saratov: "Саратов",
  tyumen: "Тюмень",
  irkutsk: "Иркутск",
  khabarovsk: "Хабаровск",
  vladivostok: "Владивосток",
  yaroslavl: "Ярославль",
  tomsk: "Томск",
  kaliningrad: "Калининград",
  sochi: "Сочи",
  "united states": "США",
  germany: "Германия",
  france: "Франция",
  china: "Китай",
  belarus: "Беларусь",
  kazakhstan: "Казахстан",
};

function whereLabel(row: { geo?: string }) {
  const geo = (row.geo || "").trim();
  if (!geo) return "—";
  if (geo === "LAN") return "Локальная сеть";
  return geo.split(",").map((part) => PLACE_RU[part.trim().toLowerCase()] || part.trim()).filter(Boolean).join(", ");
}

function AccessFields({ form, setForm, withDevice, withOs = true }: { form: any; setForm: (next: any) => void; withDevice?: boolean; withOs?: boolean }) {
  return (
    <>
      {withDevice && (
        <label className="field">
          <span>Устройство</span>
          <input placeholder="Ноутбук, ПК" value={form.deviceName || ""} onChange={(e) => setForm({ ...form, deviceName: e.target.value })} />
        </label>
      )}
      {withOs && (
      <label className="field">
        <span>Операционная система</span>
        <select value={form.osName || ""} onChange={(e) => setForm({ ...form, osName: e.target.value })}>
          <option value="">Не указана</option>
          {["Windows", "macOS", "Linux", "Android", "iOS", "RouterOS", "Keenetic"].map((os) => (
            <option key={os} value={os}>{os}</option>
          ))}
        </select>
      </label>
      )}
      <label className="field">
        <span>Срок доступа</span>
        <select value={form.accessDays || ""} onChange={(e) => setForm({ ...form, accessDays: e.target.value })}>
          <option value="">Бессрочно</option>
          <option value="7">7 дней</option>
          <option value="30">30 дней</option>
          <option value="90">90 дней</option>
          <option value="180">180 дней</option>
          <option value="365">1 год</option>
        </select>
      </label>
    </>
  );
}

function accessLabel(status: string) {
  const map: Record<string, string> = {
    ACTIVE: "Выдан",
    PENDING: "Ожидает",
    BLOCKED: "Заблокирован",
    REVOKED: "Отозван",
    EXPIRED: "Истёк",
    NONE: "Нет профиля",
    ISSUED: "Выдан",
  };
  return map[(status || "").toUpperCase()] || status || "—";
}

function roleLabel(role: string) {
  const map: Record<string, string> = {
    USER: "Сотрудник",
    IT_STAFF: "Сотрудник ИТ",
    IT_LEAD: "Руководитель ИТ",
    SECURITY: "Служба безопасности",
    AUDITOR: "Аудитор",
    ADMIN: "Администратор",
  };
  return map[(role || "").toUpperCase()] || role || "—";
}

const STAFF_ROLES = ["ADMIN", "IT_LEAD", "IT_STAFF", "SECURITY", "AUDITOR"];

function isStaffRole(role?: string) {
  return STAFF_ROLES.includes((role || "").toUpperCase());
}

function connectionLabel(online: boolean) {
  return online ? "В сети" : "Не в сети";
}

function DeleteButton({
  onDelete,
  onError,
  tiny = false,
}: {
  onDelete: () => Promise<void>;
  onError?: (message: string) => void;
  tiny?: boolean;
}) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <button
      type="button"
      className={`btn danger ${tiny ? "tiny" : ""}`}
      disabled={busy}
      onClick={async (e) => {
        e.stopPropagation();
        if (!armed) {
          setArmed(true);
          return;
        }
        setBusy(true);
        try {
          await onDelete();
        } catch (ex: any) {
          onError?.(ex.message || "Не удалось удалить");
          setArmed(false);
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? "Удаление…" : armed ? "Подтвердить удаление" : "Удалить"}
    </button>
  );
}

function UserActions({
  user,
  meEmail,
  onChanged,
  onError,
  canManage = false,
}: {
  user: any;
  meEmail: string;
  onChanged: (next: any) => void;
  onError?: (message: string) => void;
  canManage?: boolean;
}) {
  const [busy, setBusy] = useState("");
  const self = user.email === meEmail;
  const account = accountLabel(user);
  async function run(kind: string, call: () => Promise<any>) {
    setBusy(kind);
    try {
      onChanged(await call());
    } catch (ex: any) {
      onError?.(ex.message || "Не удалось изменить доступ");
    } finally {
      setBusy("");
    }
  }
  if (!canManage || self || user.approval === "PENDING_APPROVAL" || user.approval === "REJECTED") return <span className={pill(account.pill)}>{account.text}</span>;
  return (
    <div className="toolbar">
      {user.blocked || user.isActive === false ? (
        <button type="button" className="btn tiny" disabled={!!busy} onClick={() => run("unblock", () => api.unblockUser(user.id))}>
          {busy === "unblock" ? "…" : "Разблокировать"}
        </button>
      ) : (
        <button type="button" className="btn danger tiny" disabled={!!busy} onClick={() => run("block", () => api.blockUser(user.id))}>
          {busy === "block" ? "…" : "Заблокировать"}
        </button>
      )}
      {!(user.blocked || user.isActive === false) && (
        user.suspended ? (
          <button type="button" className="btn tiny" disabled={!!busy} onClick={() => run("resume", () => api.resumeUser(user.id))}>
            {busy === "resume" ? "…" : "Возобновить"}
          </button>
        ) : (
          <button type="button" className="btn ghost tiny" disabled={!!busy} onClick={() => run("suspend", () => api.suspendUser(user.id))}>
            {busy === "suspend" ? "…" : "Приостановить"}
          </button>
        )
      )}
    </div>
  );
}

function SiteActions({ site, canUnlock, onChanged, onError }: { site: any; canUnlock?: boolean; onChanged: (next: any) => void; onError?: (message: string) => void }) {
  const [busy, setBusy] = useState("");
  async function run(kind: string, call: () => Promise<any>) {
    setBusy(kind);
    try {
      onChanged(await call());
    } catch (ex: any) {
      onError?.(ex.message || "Не удалось изменить объект");
    } finally {
      setBusy("");
    }
  }
  if (site.keyLocked) {
    if (!canUnlock) return <span className="pill bad">Заблокирован</span>;
    return (
      <button type="button" className="btn tiny" disabled={!!busy} onClick={() => run("unlock", () => api.unblockSite(site.id))}>
        {busy === "unlock" ? "…" : "Разблокировать"}
      </button>
    );
  }
  if (site.suspended) {
    return (
      <button type="button" className="btn tiny" disabled={!!busy} onClick={() => run("resume", () => api.resumeSite(site.id))}>
        {busy === "resume" ? "…" : "Возобновить"}
      </button>
    );
  }
  if (site.disconnected) {
    return (
      <button type="button" className="btn tiny" disabled={!!busy} onClick={() => run("connect", () => api.connectSite(site.id))}>
        {busy === "connect" ? "…" : "Включить"}
      </button>
    );
  }
  if (!site.vpnEnabled) return null;
  return (
    <>
      <button type="button" className="btn ghost tiny" disabled={!!busy} onClick={() => run("suspend", () => api.suspendSite(site.id))}>
        {busy === "suspend" ? "…" : "Приостановить"}
      </button>
      <button type="button" className="btn danger tiny" disabled={!!busy} onClick={() => run("disconnect", () => api.disconnectSite(site.id))}>
        {busy === "disconnect" ? "…" : "Отключить"}
      </button>
    </>
  );
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

function CopyConfigButton({ userId, siteId, className = "btn ghost" }: { userId?: string; siteId?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={className}
      onClick={async (e) => {
        e.stopPropagation();
        const vpn = siteId ? await api.siteVpn(siteId) : await api.userVpn(userId || "");
        if (!vpn.config) return;
        await copyText(vpn.config);
        api.noteKeyCopy({ ...(siteId ? { siteId } : { userId }), action: "copy" }).catch(() => {});
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1600);
      }}
    >
      {copied ? "Скопировано" : "Скопировать"}
    </button>
  );
}

function ConfigBox({
  title,
  filename,
  config,
  vpnIp,
  userId,
  siteId,
}: {
  title: string;
  filename: string;
  config: string;
  vpnIp?: string;
  userId?: string;
  siteId?: string;
}) {
  const [copied, setCopied] = useState(false);
  if (!config) return null;
  async function copy() {
    await copyText(config);
    if (userId || siteId) api.noteKeyCopy({ ...(siteId ? { siteId } : { userId }), action: "copy" }).catch(() => {});
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }
  return (
    <div className="card wg-config span-2">
      <div className="k">Конфиг WireGuard</div>
      <p className="muted">
        {title}
        {vpnIp ? ` · VPN IP ${vpnIp}` : ""}
      </p>
      <pre className="wg-pre">{config}</pre>
      <div className="toolbar">
        {siteId && <button type="button" className="btn marking" onClick={() => window.dispatchEvent(new CustomEvent('vpn:setup-router', { detail: { siteId, name: title } }))}>Настроить роутер</button>}
        {!siteId && <button type="button" className="btn marking" onClick={() => saveTextFile(filename, config)}>
          Скачать
        </button>}
        <button type="button" className="btn ghost" onClick={copy}>
          {copied ? "Скопировано" : "Скопировать"}
        </button>
      </div>
    </div>
  );
}

function BlockedBanner({ by }: { by?: string }) {
  return (
    <div className="login">
      <div className="login-card blocked-card">
        <div className="eyebrow">доступ закрыт</div>
        <h1>Вы заблокированы</h1>
        <p>Прошу обратиться.</p>
        <div className="blocked-by">Заблокировал: <b>{by || "администратор"}</b></div>
      </div>
    </div>
  );
}

function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<any>(null);
  const [err, setErr] = useState("");
  const [lockUntil, setLockUntil] = useState(0);
  const [left, setLeft] = useState(0);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  useEffect(() => {
    if (!lockUntil) return;
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((lockUntil - Date.now()) / 1000));
      setLeft(seconds);
      if (!seconds) setLockUntil(0);
    };
    tick();
    const timer = window.setInterval(tick, 250);
    return () => window.clearInterval(timer);
  }, [lockUntil]);
  function enter(out: { token: string; role: string; fullName: string; email: string }) {
    setToken(out.token);
    localStorage.setItem("kontur_name", out.fullName);
    localStorage.setItem("kontur_role", out.role);
    localStorage.setItem("kontur_email", out.email);
    nav("/");
  }
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting.current || left > 0) return;
    submitting.current = true;
    setBusy(true);
    setErr("");
    try {
      if (step?.challenge) {
        const done = await api.confirmTotp(step.challenge, code);
        if (done.blocked) {
          setStep({ blocked: true, blockedBy: done.blockedBy });
          return;
        }
        enter(done);
        return;
      }
      const out = await api.login(email, password);
      if (out.blocked) {
        setStep({ blocked: true, blockedBy: out.blockedBy });
        return;
      }
      if (out.totpSetup || out.totpRequired) {
        setStep(out);
        setCode("");
        return;
      }
      enter(out);
    } catch (ex: any) {
      const retry = Number(ex.retryAfter || 0);
      if (retry > 0) {
        setLockUntil(Date.now() + retry * 1000);
        setErr("");
        return;
      }
      setErr(ex.message);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  const lockText = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  if (step?.blocked) return <BlockedBanner by={step.blockedBy} />;
  return (
    <div className="login">
      <form className="login-card" onSubmit={onSubmit} aria-busy={busy}>
        <div className="login-brand"><BrandMark /><span>FORTIS</span></div>
        <h1>Вход в систему</h1>
        {!step && (
          <>
            <label htmlFor="email">Логин</label>
            <input id="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
            <label htmlFor="password">Пароль</label>
            <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </>
        )}
        {step?.totpSetup && (
          <>
            <p>Для учётных записей управления нужен второй шаг. Отсканируйте код в приложении-аутентификаторе и введите шестизначный код.</p>
            {step.qr && <img className="totp-qr" src={step.qr} alt="Код для приложения" />}
            <p className="mono">{step.secret}</p>
          </>
        )}
        {step?.totpRequired && <p>Введите код из приложения-аутентификатора.</p>}
        {step && (
          <>
            <label htmlFor="code">Код</label>
            <input id="code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required />
          </>
        )}
        {left > 0 ? (
          <div className="lock-wait" role="status">
            <svg className="lock-clock" viewBox="0 0 32 32" aria-hidden="true">
              <circle cx="16" cy="16" r="12.5" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <circle cx="16" cy="16" r="1.4" fill="currentColor" />
              <line className="hand hour" x1="16" y1="16" x2="16" y2="9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
              <line className="hand minute" x1="16" y1="16" x2="22" y2="16" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
              <line className="hand second" x1="16" y1="17" x2="16" y2="5.5" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
            </svg>
            <span>Слишком много попыток. Повторите через {lockText}</span>
          </div>
        ) : (
          <div className="err">{err}</div>
        )}
        <button className="btn marking" type="submit" disabled={busy || left > 0}>{busy ? 'Проверка…' : step ? "Подтвердить" : "Войти"}</button>
      </form>
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="top-clock">
      <div>{now.toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Moscow" })}</div>
      <small>{now.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Moscow" })} МСК</small>
    </div>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const {pathname, search} = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState('');
  const menuButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (document.getElementById('app-navigation')?.contains(document.activeElement) && window.matchMedia('(max-width:860px)').matches) menuButton.current?.focus();
    setMenuOpen(false);
  }, [pathname]);
  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setMenuOpen(false); menuButton.current?.focus(); }
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [menuOpen]);
  const [name, setName] = useState(localStorage.getItem("kontur_name") || "");
  const [role, setRole] = useState(localStorage.getItem("kontur_role") || "");
  const [blockedBy, setBlockedBy] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  useLayoutEffect(() => {
    if (ready) window.dispatchEvent(new Event('kontur:navigation'));
  }, [pathname, search, ready]);
  useLiveData(() => api.me().then((m) => {
      if (m?.blocked) {
        setBlockedBy(m.blockedBy || "");
        return;
      }
      if (m?.email) localStorage.setItem("kontur_email", m.email);
      if (m?.fullName) {
        localStorage.setItem("kontur_name", m.fullName);
        setName(m.fullName);
      }
      if (m?.role) {
        localStorage.setItem("kontur_role", m.role);
        setRole(m.role);
      }
    }).catch(() => {}).finally(() => setReady(true)));
  if (!ready) return <div className="login" />;
  if (blockedBy !== null) return <BlockedBanner by={blockedBy} />;
  return (
    <div className={`shell ${menuOpen ? "menu-open" : ""}`}>
      <a className="skip-link" href="#workspace" onClick={(event) => { event.preventDefault(); (document.getElementById("workflow-page-host") || document.getElementById("workspace"))?.focus(); }}>Перейти к содержимому</a>
      {menuOpen && <button className="menu-backdrop" aria-label="Закрыть меню" onClick={() => setMenuOpen(false)} />}
      <aside className="side" id="app-navigation">
        <div className="brand">
          <div className="brand-mark"><BrandMark /></div>
          <div>
            <b>FORTIS</b>
          </div>
        </div>
        <div className="nav-section-label">Рабочее пространство</div>
        <nav aria-label="Основная навигация" data-workflow-router="true">
          {nav.filter(([to]) => (to !== "/settings" && to !== "/audit") || role === "ADMIN").map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} data-approved-link={to === "/approved" ? "true" : undefined} data-nav-section={to === "/audit" || to === "/settings" ? "management" : "workspace"} className={({ isActive }) => (isActive ? "active" : "")}>
              <NavIcon to={to} />
              {label}
            </NavLink>
          ))}
        </nav>
        <footer className="session-actions" aria-label="Действия сеанса">
          <button
            className="btn ghost tiny"
            disabled={loggingOut}
            onClick={async () => {
              setLoggingOut(true); setLogoutError('');
              try { await api.logout(); }
              catch (error) { setLogoutError('Выход не завершён: ' + (error as Error).message); setLoggingOut(false); return; }
              clearToken();
              localStorage.removeItem("kontur_role");
              localStorage.removeItem("kontur_name");
              localStorage.removeItem("kontur_email");
              navigate("/login");
            }}
          >
            {loggingOut ? 'Завершаем сеанс…' : 'Выйти'}
          </button>
          {logoutError && <p role="alert" className="error-state">{logoutError}</p>}
        </footer>
      </aside>
      <div className="main">
        <header className="topbar">
          <button ref={menuButton} className="menu-toggle btn ghost" aria-controls="app-navigation" aria-expanded={menuOpen} aria-label={menuOpen ? "Закрыть меню" : "Открыть меню"} onClick={() => setMenuOpen(!menuOpen)}><svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button>
          <div className="breadcrumb"><span>Рабочее пространство</span><span aria-hidden="true">/</span><b>{nav.find(([to]) => to === pathname)?.[1] || (pathname.startsWith('/settings/') ? 'Настройки' : 'Карточка')}</b></div>
          <div className="top-meta">
            {["ADMIN", "IT_LEAD", "IT_STAFF"].includes(role) && <ApprovalBell />}
            <Clock />
            <div className="avatar" title={`${name} · ${roleLabel(role)}`}>{initials(name)}</div>
          </div>
        </header>
        <main className="content" id="workspace" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}

function KpiIcon({ name }: { name: "users" | "live" | "traffic" | "keys" | "cpu" | "sites" }) {
  const p = { width: 22, height: 22, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (name === "users") return <svg {...p}><path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2" /><circle cx="9.5" cy="7" r="3.5" /><path d="M20 8v6M17 11h6" /></svg>;
  if (name === "live") return <svg {...p}><path d="M5 12.5h3l2-7 4 14 2-7h3" /><circle cx="20" cy="12" r="1.2" fill="currentColor" /></svg>;
  if (name === "traffic") return <svg {...p}><path d="M7 17V7m0 0 3 3M7 7 4 10M17 7v10m0 0 3-3m-3 3-3-3" /></svg>;
  if (name === "cpu") return <svg {...p}><rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3"/></svg>;
  if (name === "sites") return <svg {...p}><path d="M4 21h16M6 21V7l6-4 6 4v14M10 21v-6h4v6M10 9h4"/></svg>;
  return <svg {...p}><circle cx="12" cy="12" r="3" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.5 1.5M16.9 16.9l1.5 1.5M18.4 5.6l-1.5 1.5M7.1 16.9l-1.5 1.5" /></svg>;
}

function SessionPanel({
  title,
  rows,
  empty,
  selectedId,
  onSelect,
  action,
}: {
  title: string;
  rows: any[];
  empty: string;
  selectedId?: string;
  onSelect: (row: any) => void;
  action: ReactNode;
}) {
  return (
    <div className="table-card dash-table">
      <div className="table-head">
        <h2>{title}</h2>
        <span className="muted">{rows.length}</span>
        {action}
      </div>
      <div className="table-scroll" tabIndex={0} role="region" aria-label={title}>
        <table>
          <thead>
            <tr>
              <th>Подключение</th><th>Устройство / ОС</th><th>VPN IP</th><th>Статус</th><th>Последний раз в сети</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr className={`click ${selectedId === row.id ? "on" : ""}`} key={row.id} onClick={() => onSelect(row)}>
                <td>
                  <div className="user-cell">
                    <div className="avatar">{initials(row.name)}</div>
                    <div><button className="row-link" onClick={(event) => { event.stopPropagation(); onSelect(row); }}>{row.name}</button><small>{row.email || (row.kind === "object" ? "Объект" : "—")}</small></div>
                  </div>
                </td>
                <td>{deviceKindLabel(row.deviceType) || row.device || "—"}<small className="cell-detail">{row.os || "ОС не определена"}</small></td>
                <td className="mono">{row.vpnIp || "—"}</td>
                <td><span className={row.connectionState==='blocked'?'pill bad':pill(row.online ? "ONLINE" : "OFFLINE")}>{connectionLabels[row.connectionState] || (row.online?'В сети':'Не в сети')}</span></td>
                <td style={{fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap'}} title="Время последнего подтверждённого соединения WireGuard, по Москве">{lastOnlineLabel(row.handshakeAt, row.online)}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr><td colSpan={5}><div className="session-empty"><div className="empty-network-icon" aria-hidden="true"><PulseIcon name={title.includes("Объекты") ? "box" : "user"} /></div><b>{empty}</b><span>Выберите другой статус для просмотра подключений.</span></div></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

GlobalWorkerOptions.workerSrc = pdfWorker;

function PdfPages({ data }: { data: ArrayBuffer }) {
  const box = useRef<HTMLDivElement>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let cancel = false;
    const root = box.current;
    (async () => {
      const pdf = await getDocument({ data: data.slice(0) }).promise;
      if (cancel || !root) return;
      root.replaceChildren();
      for (let index = 1; index <= pdf.numPages; index += 1) {
        const page = await pdf.getPage(index);
        const viewport = page.getViewport({ scale: 1.35 });
        const canvas = document.createElement("canvas");
        canvas.width = viewport.width;
        canvas.height = viewport.height;
        const ctx = canvas.getContext("2d");
        if (!ctx) continue;
        await page.render({ canvas, canvasContext: ctx, viewport }).promise;
        if (cancel) return;
        root.appendChild(canvas);
      }
    })().catch((ex) => { if (!cancel) setErr(ex?.message || "Не удалось показать PDF"); });
    return () => { cancel = true; };
  }, [data]);
  return (
    <div className="doc-pages" ref={box}>
      {err && <p className="err">{err}</p>}
    </div>
  );
}

function DocumentViewer({ doc, onClose }: { doc: { name: string; url: string; data: ArrayBuffer } | null; onClose: () => void }) {
  if (!doc) return null;
  return (
    <div className="doc-view" onClick={onClose}>
      <div className="doc-sheet" onClick={(e) => e.stopPropagation()}>
        <div className="doc-bar">
          <b>{doc.name}</b>
          <div className="toolbar">
            <a className="btn ghost tiny" href={(window as any).panelUrl(doc.url)} download={doc.name}>Скачать</a>
            <button type="button" className="btn tiny" onClick={onClose}>Закрыть</button>
          </div>
        </div>
        <PdfPages data={doc.data} />
      </div>
    </div>
  );
}

function useDocumentViewer() {
  const [doc, setDoc] = useState<{ name: string; url: string; data: ArrayBuffer } | null>(null);
  const [err, setErr] = useState("");
  async function open(id: string, filename: string) {
    setErr("");
    try {
      const blob = await api.documentBlob(id);
      const data = await blob.arrayBuffer();
      const file = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(file);
      setDoc((prev) => {
        if (prev) URL.revokeObjectURL(prev.url);
        return { name: filename || "Документ", url, data };
      });
    } catch (ex: any) {
      const message = ex.message || "Не удалось открыть документ";
      setErr(message);
      throw new Error(message);
    }
  }
  function close() {
    setDoc((prev) => {
      if (prev) URL.revokeObjectURL(prev.url);
      return null;
    });
  }
  return { open, err, view: <>{err && !doc && <div className="err">{err}</div>}<DocumentViewer doc={doc} onClose={close} /></> };
}

function sizeLabel(bytes: number) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} Б`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} КБ`;
  return `${(value / 1048576).toFixed(1)} МБ`;
}


function PulseIcon({ name }: { name: string }) {
  const p = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (name === "up") return <svg {...p}><path d="M12 19V5M6 11l6-6 6 6" /></svg>;
  if (name === "down") return <svg {...p}><path d="M12 5v14M6 13l6 6 6-6" /></svg>;
  if (name === "user") return <svg {...p}><circle cx="12" cy="8" r="3.2" /><path d="M5 19c1.4-3 3.8-4.5 7-4.5S17.6 16 19 19" /></svg>;
  if (name === "box") return <svg {...p}><path d="M4 8.5 12 4l8 4.5v7L12 20l-8-4.5z" /><path d="M12 12.2 20 8.5M12 12.2V20M12 12.2 4 8.5" /></svg>;
  return <svg {...p}><path d="M12 4a8 8 0 1 0 8 8" /><path d="M12 12l4-2" /></svg>;
}


function ChannelWidget({ channels }: { channels: any }) {
  return <NetworkChannels channels={channels} />;
}


function SessionFacts({ selected, onClose, onDelete, navigate }: { selected: any; onClose: () => void; onDelete: () => Promise<void>; navigate: (path: string) => void }) {
  return (
    <>
      <div className="person">
        <div className="avatar">{initials(selected.name || selected.fullName)}</div>
        <div style={{ flex: 1 }}>
          <h2>{selected.name || selected.fullName}</h2>
          <div className="muted">{selected.email || (selected.kind === "object" ? "Объект" : "")}</div>
        </div>
        <button className="btn ghost tiny" onClick={onClose}>✕</button>
      </div>
      <div className="info-row"><span>Устройство</span><b>{deviceKindLabel(selected.deviceType) || selected.device || "—"}</b></div>
      <div className="info-row"><span>MAC оборудования</span><b title="Обычный WireGuard передаёт IP-пакеты, но не MAC-адрес сетевой карты удалённого устройства. Для получения MAC нужна информация от самого устройства.">Недоступен через WireGuard</b></div>
      <div className="info-row"><span>Система</span><b>{selected.os || "Не указана"}</b></div>
      <div className="info-row"><span>Откуда</span><b className="mono">{publicIp(selected.endpoint) || "—"}</b></div>
      <div className="info-row"><span>Провайдер</span><b>{selected.isp || "—"}</b></div>
      {selected.kind === "object" && <section aria-label="Контакты провайдера">
        <h3>Провайдер объекта</h3>
        <div className="info-row contact-fact"><span>Название</span><b>{selected.providerName || "Не указано"}</b></div>
        <div className="info-row contact-fact"><span>Телефон провайдера</span><b>{selected.providerPhone || "Не указан"}</b></div>
        <div className="info-row contact-fact"><span>Почта провайдера</span><b>{selected.providerEmail || "Не указана"}</b></div>
      </section>}
      <div className="info-row"><span>Где</span><b>{whereLabel(selected)}</b></div>
      <div className="info-row"><span>VPN IP</span><b className="mono">{selected.vpnIp || "—"}</b></div>
      <div className="info-row"><span>Срок доступа</span><b><span className={pill(accessTone(selected.accessUntil).pill)}>{accessTone(selected.accessUntil).text}</span></b></div>
      <div className="info-row"><span>Handshake</span><b>{creationDateLabel(selected.handshakeAt)}</b></div>
      <div className="info-row"><span>Подключение</span><span className={pill(selected.online ? "ONLINE" : "OFFLINE")}>{selected.online ? "Онлайн" : "Вне сети"}</span></div>
      {selected.kind === 'object' && ['ADMIN', 'IT_LEAD', 'IT_STAFF'].includes(localStorage.getItem('kontur_role') || '') && <SitePing key={selected.siteId || selected.id} site={selected} externalIp={publicIp(selected.endpoint)} />}
      <div className="toolbar" style={{ marginTop: 14 }}>
        {selected.kind !== "object" && selected.userId && (
          <button className="btn marking" onClick={() => navigate(`/users/${selected.userId}`)}>Открыть карточку</button>
        )}
        {selected.kind === "object" && (
          <button className="btn marking" onClick={() => navigate("/sites")}>К объектам</button>
        )}
        {selected.kind !== "object" && selected.userId && selected.account !== "pending" && selected.account !== "rejected" && (
          <button className="btn ghost" onClick={() => api.userVpn(selected.userId).then((vpn) => { if (!vpn.config) return; saveTextFile(vpn.filename, vpn.config); api.noteKeyCopy({ userId: selected.userId, action: "download" }).catch(() => {}); })}>Скачать</button>
        )}
        {localStorage.getItem("kontur_role") === "ADMIN" && selected.kind !== "object" && selected.userId && selected.email !== localStorage.getItem("kontur_email") && (
          <DeleteButton onError={(message) => alert(message)} onDelete={onDelete} />
        )}
      </div>
    </>
  );
}

function Home() {
  const navigate = useNavigate();
  const docs = useDocumentViewer();
  const [params, setParams] = useSearchParams();
  const [d, setD] = useState<any>(null);
  const [loadError, setLoadError] = useState("");
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [employeeFilter,setEmployeeFilter]=useState('online');
  const [siteFilter,setSiteFilter]=useState('online');
  const [selected, setSelected] = useState<any>(null);
  const [loadedCard, setCard] = useState<any>(null);
  const [cardErr, setCardErr] = useState("");
  const [cardFloor, setCardFloor] = useState(0);
  const cardBox = useRef<HTMLDivElement>(null);
  const scrollLock = useRef<number | null>(null);
  const openUser = params.get("user") || "";
  const card = loadedCard?.id === openUser ? loadedCard : null;
  useEffect(() => {
    let stop = false;
    const load = () => api.dashboard()
        .then((next) => {
          if (stop) return;
          setD(next);
          setLoadError("");
          setUpdatedAt(new Date());
          setSelected((cur: any) => {
            if (!cur) return cur;
            return (next.sessions || []).find((row: any) => row.id === cur.id) || null;
          });
        })
        .catch(() => { if (!stop) setLoadError("Не удалось обновить данные. Повторяем запрос автоматически; последние показания могут быть устаревшими."); });
    const stopRefresh = startLiveRefresh(load);
    return () => {
      stop = true;
      stopRefresh();
    };
  }, []);
  useEffect(() => {
    setCard(null);
    setCardErr("");
    if (!openUser) return;
    let stop = false;
    const loadCard = () => api.user(openUser)
      .then((user) => { if (!stop) { setCard(user); setCardErr(""); } })
      .catch((ex) => { if (!stop) setCardErr(ex.message || "Сотрудник не найден"); });
    const stopRefresh = startLiveRefresh(loadCard);
    return () => {
      stop = true;
      stopRefresh();
    };
  }, [openUser]);
  const sessions = d?.sessions || [];
  useLayoutEffect(() => {
    const el = cardBox.current;
    if (!el) return;
    const next = el.scrollHeight;
    if (next > cardFloor) setCardFloor(next);
    const scroller = document.querySelector(".content");
    if (scrollLock.current != null && scroller instanceof HTMLElement) scroller.scrollTop = scrollLock.current;
    scrollLock.current = null;
  });
  function pick(row: any) {
    const scroller = document.querySelector(".content");
    scrollLock.current = scroller instanceof HTMLElement ? scroller.scrollTop : 0;
    setSelected(row);
    if (row?.kind !== "object" && row?.userId) setParams({ user: row.userId }, { replace: true });
    else setParams({}, { replace: true });
  }
  if (!d) return loadError ? <div className="error-state" role="alert"><h1>Данные временно недоступны</h1><p>{loadError}</p></div> : <div className="dashboard-skeleton" role="status" aria-label="Загружаем состояние VPN"><div /><div /><div /></div>;
  return (
    <div className="dash">
      {docs.view}
      <div className="panel">
        <div className="dash-head">
          <div>
            <div className="eyebrow">Мониторинг</div>
            <h1>Обзор сети</h1>
            <p className="muted">Текущие VPN-подключения, трафик и состояние сервера.</p>
          </div>
          <div className={`refresh-state ${loadError ? "stale" : ""}`} role="status"><span className="status-dot" /><div><b>{loadError ? "Нет обновления" : "Данные обновляются"}</b><small>{updatedAt ? `Последнее обновление ${updatedAt.toLocaleTimeString("ru-RU", {timeZone:"Europe/Moscow"})} МСК` : "Ожидаем данные"}</small></div></div>
        </div>
        {loadError && <div className="error-state" role="alert">{loadError}</div>}
        <div className="kpis">
          <div className="kpi">
            <div className="kpi-ico blue"><KpiIcon name="users" /></div>
            <ConnectionStates title="Сотрудники" counts={d.employeeStates} value={employeeFilter} onChange={setEmployeeFilter} />
          </div>
          <div className="kpi">
            <div className="kpi-ico violet"><KpiIcon name="sites" /></div>
            <ConnectionStates title="Объекты" counts={d.siteStates} value={siteFilter} onChange={setSiteFilter} />
          </div>
          <div className="kpi">
            <div className="kpi-ico green"><KpiIcon name="traffic" /></div>
            <TrafficSummary channels={d.channels} />
          </div>
          <div className="kpi">
            <div className="kpi-ico cyan"><KpiIcon name="cpu" /></div>
            <ServerLoad channels={d.channels} />
          </div>
        </div>
        <div className="dashboard-context"><span><i className="status-dot" />Онлайн — входящая активность за последние 25 секунд. Для стабильного статуса обновите конфигурацию: keepalive 10 секунд.</span><div><button className="btn ghost tiny" onClick={() => navigate("/users")}>Управление пользователями <span aria-hidden="true">↗</span></button><button className="btn ghost tiny" onClick={() => navigate("/sites")}>Объекты <span aria-hidden="true">↗</span></button></div></div>
        <ChannelWidget channels={d.channels} />
        {openUser && !card && <section className="profile-card" aria-label="Карточка сотрудника">
          <div className="h-row"><h2>Карточка сотрудника</h2><button className="btn ghost tiny" aria-label="Закрыть карточку" onClick={() => { setCardFloor(0); setSelected(null); setParams({}, { replace: true }); }}>✕</button></div>
          {cardErr ? <p className="err" role="alert">{cardErr}</p> : <p role="status">Загрузка карточки…</p>}
        </section>}
        {(card || (selected && selected.kind === "object")) && (
          <div className="profile-card" ref={cardBox} style={cardFloor ? { minHeight: cardFloor } : undefined}>
            {card ? (
              <>
                <div className="person">
                  <div className="avatar">{initials(card.fullName)}</div>
                  <div style={{ flex: 1 }}>
                    <h2>{card.fullName}</h2>
                    <div className="muted">{card.email}</div>
                    <div style={{ marginTop: 6 }}>
                      <span className={pill(accountLabel(card).pill)}>{accountLabel(card).text}</span>
                      {" "}
                      <span className={pill(card.online ? "ONLINE" : "OFFLINE")}>{card.online ? "В сети" : "Вне сети"}</span>
                    </div>
                  </div>
                  <button className="btn ghost tiny" onClick={() => { setCardFloor(0); setCard(null); setSelected(null); setParams({}, { replace: true }); }}>✕</button>
                </div>
                {cardErr && <div className="err">{cardErr}</div>}
                <div className="fact-grid">
                  <div className="info-row"><span>VPN IP</span><b className="mono">{card.vpnIp || "—"}</b></div>
                  <div className="info-row"><span>Должность</span><b>{card.title || "—"}</b></div>
                  <div className="info-row"><span>Компания</span><b>{card.company || "—"}</b></div>
                  <div className="info-row"><span>Подразделение</span><b>{card.department || "—"}</b></div>
                  <div className="info-row contact-fact"><span>Контактный телефон · AD</span><b>{card.phone || "Не указан в AD"}</b></div>
                  <div className="info-row contact-fact"><span>Контактная почта · AD</span><b>{card.contactEmail || "Не указана в AD"}</b></div>
                  <div className="info-row"><span>Устройство</span><b>{deviceKindLabel(card.deviceType) || card.deviceName || "—"}</b></div>
                  <div className="info-row"><span>Система</span><b>{card.osName || "Не указана"}</b></div>
                  <div className="info-row"><span>Откуда</span><b className="mono">{publicIp(card.endpoint) || "—"}</b></div>
                  <div className="info-row"><span>Провайдер</span><b>{card.isp || "—"}</b></div>
                  <div className="info-row"><span>Где</span><b>{whereLabel({ geo: card.lastGeo })}</b></div>
                  <div className="info-row"><span>Срок доступа</span><b><span className={pill(accessTone(card.accessUntil).pill)}>{accessTone(card.accessUntil).text}</span></b></div>
                  <div className="info-row"><span>Туннель</span><b>{card.suspended ? "Приостановлен" : card.vpnEnabled ? "Включён" : "Выключен"}</b></div>
                  <div className="info-row"><span>Handshake</span><b>{creationDateLabel(card.handshakeAt)}</b></div>
                </div>
                <div className="access-block">
                  <h3>Сейчас открывает</h3>
                  <p className="muted">Внутренние ресурсы, доступные через WireGuard. Журнал хранится на сервере.</p>
                  {(card.accessNow || []).length ? (
                    <ul className="access-live">
                      {(card.accessNow || []).map((row: any) => (
                        <li key={row.id}><b>{row.resource}</b> <span className="mono">{row.destination}:{row.port}</span> {row.download ? `· скачано ${sizeLabel(row.bytesDown)}` : "· открыто"}</li>
                      ))}
                    </ul>
                  ) : <p className="muted">Сейчас нет открытых внутренних ресурсов</p>}
                  <h3>Журнал обращений</h3>
                  <div className="table-card">
                    <table>
                      <thead><tr><th>Когда</th><th>Ресурс</th><th>Куда</th><th>Скачано</th><th>Отправлено</th></tr></thead>
                      <tbody>
                        {(card.accessJournal || []).map((row: any) => (
                          <tr key={row.id}>
                            <td>{creationDateLabel(row.openedAt)}{row.live ? " · сейчас" : ""}</td>
                            <td>{row.resource}</td>
                            <td className="mono">{row.destination}:{row.port}</td>
                            <td>{sizeLabel(row.bytesDown)}</td>
                            <td>{sizeLabel(row.bytesUp)}</td>
                          </tr>
                        ))}
                        {!(card.accessJournal || []).length && <tr><td colSpan={5} className="muted">Пока нет обращений к внутренним ресурсам</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="info-row"><span>Служебная записка</span><b>{(card.documents || []).length ? (card.documents || []).map((doc: any) => (
                  <button key={doc.id} type="button" className="btn ghost tiny" style={{ marginLeft: 6 }} onClick={() => docs.open(doc.id, doc.filename).catch((ex) => setCardErr(ex.message))}>{doc.filename}</button>
                )) : "—"}</b></div>
              </>
            ) : (
              <SessionFacts
                selected={selected}
                onClose={() => setSelected(null)}
                navigate={navigate}
                onDelete={async () => {
                  await api.deleteUser(selected.userId);
                  setSelected(null);
                }}
              />
            )}
          </div>
        )}
        <div className="dash-body">
        <div className="dash-split">
          <SessionPanel
            title={`Сотрудники · ${connectionLabels[employeeFilter]}`}
            rows={sessions.filter((row: any) => row.kind !== "object" && row.connectionState===employeeFilter)}
            empty="Сотрудников с выбранным статусом нет"
            selectedId={selected?.id || sessions.find((row: any) => row.userId === openUser)?.id}
            onSelect={pick}
            action={<button className="btn ghost tiny" onClick={() => navigate("/users")}>Все пользователи ↗</button>}
          />
          <SessionPanel
            title={`Объекты · ${connectionLabels[siteFilter]}`}
            rows={sessions.filter((row: any) => row.kind === "object" && row.connectionState===siteFilter)}
            empty="Объектов с выбранным статусом нет"
            selectedId={selected?.kind === "object" ? selected.id : ""}
            onSelect={pick}
            action={<button className="btn ghost tiny" onClick={() => navigate("/sites")}>Все объекты ↗</button>}
          />
        </div>
        </div>
      </div>
    </div>
  );
}

function Users() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [rows, setRows] = useState<any[]>([]);
  const [err, setErr] = useState("");
  const [issued, setIssued] = useState<any>(null);
  const [meEmail, setMeEmail] = useState(localStorage.getItem("kontur_email") || "");
  const [meRole, setMeRole] = useState(localStorage.getItem("kontur_role") || "");
  const load = async () => {
    const u = await api.users();
    setRows(u.data || []);
  };
  useEffect(() => {
    load().catch((e) => setErr(e.message));
    api.me().then((m) => {
      if (m?.email) {
        localStorage.setItem("kontur_email", m.email);
        setMeEmail(m.email);
      }
      if (m?.role) {
        localStorage.setItem("kontur_role", m.role);
        setMeRole(m.role);
      }
    }).catch(() => {});
  }, []);
  async function openConfig(row: any, download = false) {
    setErr("");
    try {
      const vpn = await api.userVpn(row.id);
      setIssued({ userId: row.id, fullName: row.fullName, ...vpn });
      api.noteKeyCopy({ userId: row.id, action: download ? "download" : "open" }).catch(() => {});
      if (download && vpn.config) saveTextFile(vpn.filename, vpn.config);
    } catch (ex: any) {
      setErr(ex.message || "Не удалось получить конфиг");
    }
  }
  async function removeUser(row: any) {
    setErr("");
    await api.deleteUser(row.id);
    setIssued(null);
    await load();
  }
  const filtered = rows.filter((u) => !isStaffRole(u.role)).filter((u) => {
    const s = q.toLowerCase();
    if (!s) return true;
    return `${u.fullName} ${u.email} ${u.vpnIp} ${u.company} ${u.title}`.toLowerCase().includes(s);
  });
  const blocked = filtered.filter((u) => accountLabel(u).text === "Заблокирован");
  const active = filtered.filter((u) => accountLabel(u).text !== "Заблокирован");
  const renderUser = (u: any) => (
    <tr className={`click ${issued?.userId === u.id ? "on" : ""}`} key={u.id} onClick={() => { if (keyReleased(u.approval)) openConfig(u, false); }}>
      <td>
        <div className="user-cell">
          <div className="avatar">{initials(u.fullName)}</div>
          <div>{u.fullName}<small>{u.email}</small></div>
        </div>
      </td>
      <td>
        <span className={pill(accountLabel(u).pill)}>{accountLabel(u).text}</span>
        {u.blocked && u.blockReason ? <small style={{ display: "block", color: "var(--muted)" }}>{u.blockReason}</small> : null}
      </td>
      <td><span className={pill(u.online ? "ONLINE" : "OFFLINE")}>{u.online ? "В сети" : "Вне сети"}</span></td>
      <td className="mono">{u.vpnIp || "—"}</td>
      <td>{u.title || "—"}</td>
      <td>{roleLabel(u.role)}</td>
      <td>{u.company || "—"}</td>
      <td>
        <div className="toolbar" onClick={(e) => e.stopPropagation()}>
          <button type="button" className="btn ghost tiny" onClick={() => navigate(`/?user=${u.id}`)}>Открыть</button>
          {keyReleased(u.approval) && (
            <>
              <button type="button" className="btn marking tiny" onClick={() => openConfig(u, true)}>Скачать</button>
              <CopyConfigButton userId={u.id} className="btn ghost tiny" />
            </>
          )}
          {meRole === "ADMIN" && u.approval === "PENDING_APPROVAL" && u.approvalId && (
            <NavLink className="btn ghost tiny" to={`/approved?status=pending&focus=request:${encodeURIComponent(u.approvalId)}`}>В Согласование</NavLink>
          )}
          <UserActions user={u} meEmail={meEmail} canManage={meRole === "ADMIN"} onError={setErr} onChanged={(next) => setRows((rows) => rows.map((row) => row.id === next.id ? { ...row, ...next } : row))} />
          {meRole === "ADMIN" && u.email !== meEmail && (
            <DeleteButton tiny onError={setErr} onDelete={() => removeUser(u)} />
          )}
        </div>
      </td>
    </tr>
  );
  return (
    <>
      <div className="h-row">
        <div>
          <div className="eyebrow">каталог</div>
          <h1>Пользователи</h1>
        </div>
      </div>
      <p className="muted">Сотрудники берутся из Active Directory. Объекты добавляются вручную в разделе «Объекты».</p>
      {err && <div className="err">{err}</div>}
      {issued?.config && (
        <ConfigBox
          title={`Профиль для ${issued.fullName || "сотрудника"}`}
          filename={issued.filename || issued.configName || "employee.conf"}
          config={issued.config}
          vpnIp={issued.vpnIp}
          userId={issued.userId}
        />
      )}
      <div className="table-card" style={{ marginBottom: 16 }}>
        <div className="table-head">
          <h2>Список пользователей</h2>
          <input placeholder="Поиск…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 220 }} />
        </div>
        <table>
          <thead>
            <tr><th>ФИО</th><th>Доступ</th><th>Сеть</th><th>VPN IP</th><th>Должность</th><th>Роль</th><th>Компания</th><th></th></tr>
          </thead>
          <tbody>{active.map(renderUser)}</tbody>
        </table>
        {!active.length && <div className="empty">Пользователей не найдено</div>}
      </div>
      <div className="table-card">
        <div className="table-head">
          <h2>Заблокированные</h2>
        </div>
        <table>
          <thead>
            <tr><th>ФИО</th><th>Доступ</th><th>Сеть</th><th>VPN IP</th><th>Должность</th><th>Роль</th><th>Компания</th><th></th></tr>
          </thead>
          <tbody>{blocked.map(renderUser)}</tbody>
        </table>
        {!blocked.length && <div className="empty">Заблокированных пользователей нет</div>}
      </div>
    </>
  );
}

function UserCard() {
  const { id } = useParams();
  return <Navigate to={`/?user=${id || ""}`} replace />;
}

function Devices() {
  const navigate = useNavigate();
  const [rows, setRows] = useState<any[]>([]);
  useLiveData(() => api.devices().then((r) => setRows(r.data || [])));
  return (
    <>
      <div className="h-row">
        <h1>Устройства</h1>
        <button className="btn marking" onClick={() => navigate("/users")}>
          Добавить сотрудника
        </button>
      </div>
      <div className="table-card">
        <table>
          <thead>
            <tr><th>Имя</th><th>Владелец</th><th>Контур</th><th>VPN IP</th><th>Доступ</th><th>Подключение</th><th>Handshake</th></tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr className="click" key={d.id} onClick={() => navigate(`/devices/${d.id}`)}>
                <td>{d.name}</td>
                <td>{d.userName || d.siteName}</td>
                <td>{d.contour === "SITES" ? "Объекты" : "Сотрудники"}</td>
                <td className="mono">{d.vpnIp}</td>
                <td><span className={pill(d.status)}>{accessLabel(d.status)}</span></td>
                <td><span className={pill(d.online ? "ONLINE" : "OFFLINE")}>{connectionLabel(!!d.online)}</span></td>
                <td>{creationDateLabel(d.handshakeAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <div className="empty">Нет зарегистрированных устройств в этом контуре</div>}
      </div>
    </>
  );
}

function DeviceCard() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [d, setD] = useState<any>(null);
  const load = () => api.device(id!).then(setD);
  useLiveData(load, [id]);
  if (!d) return <p>Загрузка…</p>;
  return (
    <div className="detail">
      <div>
        <div className="eyebrow">карточка устройства</div>
        <h1>{d.name}</h1>
        <p className="muted">
          {d.userId ? (
            <button className="btn ghost" onClick={() => navigate(`/?user=${d.userId}`)}>{d.userName || "Сотрудник"}</button>
          ) : (
            d.userName || d.siteName
          )}
          {d.company ? ` · ${d.company}` : ""}{d.department ? ` · ${d.department}` : ""}
        </p>
        <div className="card kv" style={{ marginTop: 16 }}>
          <b>VPN IP</b><span className="mono">{d.vpnIp}</span>
          <b>Внешний IP</b><span>{d.lastExternalIp || "—"}</span>
          <b>Местоположение</b><span>{d.lastGeo || "—"}</span>
          <b>ОС</b><span>{d.osName || "—"}</span>
          <b>Device ID</b><span className="mono">{d.deviceId}</span>
          <b>Public Key</b><span className="mono">{d.publicKey}</span>
          <b>Сертификат</b><span className="mono">{d.certFingerprint}</span>
          <b>Handshake</b><span>{creationDateLabel(d.handshakeAt)}</span>
          <b>Срок</b><span>{d.accessFrom ? creationDateLabel(d.accessFrom) : "—"} → {d.accessUntil ? creationDateLabel(d.accessUntil) : "бессрочно"}</span>
          <b>Статус доступа</b><span className={pill(d.status)}>{accessLabel(d.status)}</span>
          <b>Подключение</b><span className={pill(d.online ? "ONLINE" : "OFFLINE")}>{connectionLabel(!!d.online)}</span>
        </div>
        <div className="toolbar" style={{ marginTop: 16 }}>
          {d.config && (
            <button className="btn marking" onClick={() => saveTextFile(d.configName || `${d.name}.conf`, d.config)}>
              Скачать
            </button>
          )}
          <button className="btn danger" onClick={async () => { await api.blockDevice(d.id); load(); }}>Заблокировать</button>
          <button className="btn" onClick={async () => { await api.unblockDevice(d.id); load(); }}>Разблокировать</button>
          <button className="btn ghost" onClick={async () => { await api.revokeDevice(d.id); load(); }}>Отозвать устройство</button>
        </div>
        {d.config && (
          <ConfigBox title={`Профиль ${d.name}`} filename={d.configName || `${d.name}.conf`} config={d.config} vpnIp={d.vpnIp} />
        )}
      </div>
      <div>
        <div className="card">
          <div className="k">Разрешённые сети</div>
          {(d.networks || []).map((n: any) => <div key={n.id}>{n.name} · {n.cidr}</div>)}
          {!(d.networks || []).length && <p className="muted">Нет явных сетей — deny by default</p>}
        </div>
        <div className="card" style={{ marginTop: 12 }}>
          <div className="k">Ресурсы</div>
          {(d.resources || []).map((n: any) => <div key={n.id}>{n.name} · {n.host}</div>)}
        </div>
        {d.blockReason && <div className="card warn" style={{ marginTop: 12 }}><div className="k">Причина</div><div>{d.blockReason}</div></div>}
      </div>
    </div>
  );
}

function Sites() {
  const [role, setRole] = useState("");
  const [rows, setRows] = useState<any[]>([]);
  const [siteQuery, setSiteQuery] = useState("");
  const siteSearchInput = useRef<HTMLInputElement>(null);
  const visibleSites = rows.filter(site => matchesName(site.name, siteQuery));
  const [showCreate, setShowCreate] = useState(false);
  const [users, setUsers] = useState<any[]>([]);
  const [err, setErr] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<any>(null);
  const [form, setForm] = useState({
    name: "",
    address: "",
    lanCidr: "",
    routerName: "",
    providerName: "",
    providerPhone: "",
    providerEmail: "",
    ownerId: "",
    companyName: "",
    notes: "",
    issueVpn: true,
    osName: "",
    accessDays: "",
  });
  const load = async () => {
    const [s, u, me] = await Promise.all([api.sites(), api.users(), api.me()]);
    setRows(s.data || []);
    setUsers(u.data || []);
    setRole(me.role || "");
  };
  useLiveData(() => load().then(() => setErr("")).catch((e) => setErr(e.message)));
  async function create(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setOk("");
    setIssued(null);
    setBusy(true);
    try {
      const out = await api.createSite({
        ...form,
        ownerId: form.ownerId || null,
        companyId: null,
        companyName: form.companyName || null,
        osName: form.osName,
        accessDays: form.accessDays ? Number(form.accessDays) : null,
      });
      setOk(`Объект «${out.name}» создан. Заявка отправлена на согласование, ключ закрыт до одобрения.`);
      window.dispatchEvent(new Event('vpn:approvals-changed'));
      setIssued(null);
      setForm((f) => ({ ...f, name: "", address: "", lanCidr: "", routerName: "", notes: "", companyName: "", providerName: "", providerPhone: "", providerEmail: "" }));
      await load();
      setShowCreate(false);
    } catch (ex: any) {
      setErr(ex.message || "Не удалось создать объект");
    } finally {
      setBusy(false);
    }
  }
  async function openConfig(row: any) {
    setErr("");
    window.dispatchEvent(new CustomEvent('vpn:setup-router', {detail:{siteId:row.id,name:row.name}}));
  }
  async function removeSite(row: any) {
    setErr("");
    setOk("");
    await api.deleteSite(row.id);
    setIssued(null);
    await load();
  }
  return (
    <>
      <div className="h-row">
        <div>
          <div className="eyebrow">филиалы</div>
          <h1>Объекты</h1>
        </div>
        <button className="btn marking" type="button" aria-expanded={showCreate} aria-controls="site-create" onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Закрыть форму" : "+ Добавить объект"}</button>
      </div>
      <p className="page-intro">VPN-доступ филиалов и площадок. Каждый объект проходит цифровое согласование.</p>
      <SiteLinks sites={rows} canEdit={role === "ADMIN" || role === "IT_LEAD"}/>
      {ok && <div className="ok-msg" role="status">{ok}</div>}
      {err && <div className="error-state" role="alert">{err}</div>}
      {showCreate && <form id="site-create" className="card form-grid create-panel" onSubmit={create}>
        <h2 className="span-2">Добавить объект</h2>
        <p className="muted span-2">Объекты добавляются только вручную. Сотрудники приходят из Active Directory.</p>
        <label className="field">
          <span>Название объекта</span>
          <input placeholder='ЖК «Северный»' value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </label>
        <label className="field">
          <span>Адрес</span>
          <input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} />
        </label>
        <label className="field">
          <span>Локальная сеть</span>
          <input placeholder="192.168.50.0/24" value={form.lanCidr} onChange={(e) => setForm({ ...form, lanCidr: e.target.value })} />
        </label>
        <label className="field">
          <span>Ответственный</span>
          <select value={form.ownerId} onChange={(e) => setForm({ ...form, ownerId: e.target.value })}>
            <option value="">Текущий администратор</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>{ownerLabel(u)}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Компания</span>
          <input value={form.companyName} onChange={(e) => setForm({ ...form, companyName: e.target.value })} placeholder="Автодор" />
        </label>
        <AccessFields form={form} setForm={setForm} withOs={false} />
        <p className="muted span-2">Срок закрывает туннель объекта в указанную дату. Бессрочный доступ действует, пока объект не удалят или не отключат.</p>
        <h3 className="span-2">Провайдер объекта</h3>
        <label className="field"><span>Название провайдера</span><input maxLength={200} value={form.providerName} onChange={e => setForm({ ...form, providerName: e.target.value })} /></label>
        <label className="field"><span>Телефон провайдера</span><input type="tel" maxLength={64} value={form.providerPhone} onChange={e => setForm({ ...form, providerPhone: e.target.value })} /></label>
        <label className="field"><span>Почта провайдера</span><input type="email" maxLength={254} value={form.providerEmail} onChange={e => setForm({ ...form, providerEmail: e.target.value })} /></label>
        <p className="muted span-2">Контакты для обращения в поддержку. Необязательные поля; настройки VPN они не меняют.</p>
        <label className="field span-2">
          <span>Примечание</span>
          <textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
        </label>
        <p className="muted span-2">Ключ WireGuard закрыт, пока заявку не согласуют. После согласования его можно посмотреть и скачать.</p>
        <div className="span-2">
          <button className="btn marking" type="submit" disabled={busy}>{busy ? "Сохранение…" : "Добавить объект"}</button>
        </div>
      </form>}
      {issued?.config && (
        <ConfigBox
          title={`Профиль объекта «${issued.name || ""}»`}
          filename={issued.filename || issued.configName || "site.conf"}
          config={issued.config}
          vpnIp={issued.vpnIp}
          siteId={issued.siteId || issued.id}
        />
      )}
      <div className="table-card">
        <div className="table-head catalog-search-head">
          <h2>Список объектов</h2>
          <div className="catalog-search">
            <label htmlFor="sites-name-search">Поиск объектов по названию</label>
            <div className="catalog-search-control">
              <input id="sites-name-search" ref={siteSearchInput} type="search" placeholder="Название объекта" value={siteQuery} onChange={event => setSiteQuery(event.target.value)} aria-controls="sites-search-results" autoComplete="off" />
              {siteQuery && <button type="button" className="btn ghost" aria-label="Очистить поиск объектов" onClick={() => { setSiteQuery(""); siteSearchInput.current?.focus(); }}>Очистить</button>}
            </div>
            <small role="status">Найдено: {visibleSites.length} из {rows.length}</small>
          </div>
        </div>
        <table>
          <thead><tr><th>Объект</th><th scope="col">Дата создания</th><th>LAN</th><th>ОС</th><th>Срок</th><th>VPN IP</th><th>Доступ</th><th>Согласовал</th><th>Подключение</th><th></th></tr></thead>
          <tbody id="sites-search-results">
            {visibleSites.map((s) => (
              <tr data-site-id={s.id} className={`click ${issued?.siteId === s.id ? "on" : ""}`} key={s.id} onClick={() => { if (keyReleased(s.approval)) openConfig(s); }}>
                <td>{s.name}<small style={{ display: "block", color: "var(--muted)" }}>{s.address}</small></td>
                <td>{creationDateLabel(s.createdAt)}</td>
                <td className="mono">{s.lanCidr || "—"}</td>
                <td>{s.osName || "—"}</td>
                <td>{untilLabel(s.accessUntil)}</td>
                <td className="mono">{s.vpnIp || "—"}</td>
                <td><span className={pill(s.approval === "PENDING_APPROVAL" ? "PENDING_APPROVAL" : s.approval === "REJECTED" ? "REJECTED" : s.status)}>{s.approval === "PENDING_APPROVAL" ? "На согласовании" : s.approval === "REJECTED" ? "Отклонено СБ" : accessLabel(s.status)}</span></td>
                <td>{s.reviewedByName || s.reviewedBy || "—"}</td>
                <td><span className={pill(s.keyLocked ? "BLOCKED" : s.suspended ? "PENDING" : s.disconnected ? "BLOCKED" : s.online ? "ONLINE" : "OFFLINE")}>{s.keyLocked ? "Заблокирован" : s.suspended ? "Приостановлен" : s.disconnected ? "Отключён" : connectionLabel(!!s.online)}</span></td>
                <td>
                  <div className="toolbar" onClick={(e) => e.stopPropagation()}>
                    <SiteActions site={s} canUnlock={localStorage.getItem("kontur_role") === "ADMIN"} onError={setErr} onChanged={(next) => setRows((rows) => rows.map((row) => row.id === next.id ? { ...row, ...next } : row))} />
                    {keyReleased(s.approval) && (
                      <>
                        <button type="button" className="btn marking tiny" onClick={() => openConfig(s)}>Скачать</button>
                        <CopyConfigButton siteId={s.id} className="btn ghost tiny" />
                      </>
                    )}
                    {["ADMIN", "IT_LEAD"].includes(localStorage.getItem("kontur_role") || "") && s.approval === "PENDING_APPROVAL" && s.approvalId && (
                      <NavLink className="btn ghost tiny" to={`/approved?status=pending&focus=request:${encodeURIComponent(s.approvalId)}`}>В Согласование</NavLink>
                    )}
                    <DeleteButton tiny onError={setErr} onDelete={() => removeSite(s)} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visibleSites.length && <div className="empty">{siteQuery.trim() ? "По вашему запросу объекты не найдены. Измените название или очистите поиск." : "Объектов пока нет. Нажмите «Добавить объект», чтобы создать первую заявку."}</div>}
      </div>
    </>
  );
}

function Connections() {
  return <Incidents />;
}

function Networks() {
  const [resourceDialog,setResourceDialog]=useState<any>(null);
  const [deleting,setDeleting]=useState<any>(null);
  const [nets, setNets] = useState<any[]>([]);
  const [res, setRes] = useState<any[]>([]);
  const [sites, setSites] = useState<any[]>([]);
  const [role, setRole] = useState("");
  const [editing, setEditing] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [notice, setNotice] = useState("");
  const [onlyOnline, setOnlyOnline] = useState(false);
  const [err, setErr] = useState("");
  const load = () => Promise.all([api.networks(), api.resources(), api.sites(), api.me()]).then(([n,r,s,m]) => {
    setNets(n.data || []); setRes(r.data || []); setSites(s.data || []); setRole(m.role || ""); setErr("");
  }).catch(() => setErr("Нет связи с сервером. Повторяем обновление…"));
  useLiveData(load);
  const canEdit = role === "ADMIN" || role === "IT_LEAD";
  const connectedSites = sites.filter(s => s.vpnIp && (!onlyOnline || s.online));
  return (
    <>
      <div className="eyebrow">Инфраструктура</div>
      <h1>Сети и ресурсы</h1>
      {role && <NetworkPing />}
      <SiteLinks sites={sites} canEdit={canEdit}/>
      {resourceDialog&&<ResourceDialog resource={resourceDialog.resource} remove={resourceDialog.remove} networks={nets} onClose={()=>setResourceDialog(null)} onSaved={()=>{setResourceDialog(null);setNotice('Изменения ресурсов сохранены');load()}}/>}
      {deleting&&<DeleteNetworkDialog network={deleting} onClose={()=>setDeleting(null)} onDeleted={()=>{setDeleting(null);setNotice('Сеть и связанные правила удалены. Конфигурации сервера обновлены.');load()}}/>}
      {err && <div className="error-state" role="alert">{err}</div>}
      <p className="muted">Всё запрещено, кроме явно выданного в заявке.</p>
      {notice && <p role="status">{notice}</p>}
      {editing && <form className="card form-grid" aria-label="Редактирование сети" onSubmit={async e => {
        e.preventDefault(); if (saving) return; setSaving(true); setSaveError("");
        try { if(editing.id) await api.updateNetwork(editing.id, editing); else await api.createNetwork(editing); setEditing(null); setNotice("Сеть сохранена"); await load(); }
        catch (error: any) { setSaveError(error.message || "Не удалось сохранить сеть"); }
        finally { setSaving(false); }
      }}>
        <h2>{editing.id?'Редактирование сети':'Добавить сеть'}</h2>
        {!editing.id&&<label>Контур<select value={editing.contour} disabled={saving} onChange={e=>setEditing({...editing,contour:e.target.value})}><option value="EMPLOYEES">Сотрудники</option><option value="SITES">Объекты</option></select></label>}
        <label>Название<input autoFocus required maxLength={200} value={editing.name} disabled={saving} onChange={e => setEditing({...editing, name: e.target.value})} /></label>
        <label>Подсеть (CIDR)<input required value={editing.cidr} disabled={saving} onChange={e => setEditing({...editing, cidr: e.target.value})} /></label>
        <label>Описание<input maxLength={2000} value={editing.description || ""} disabled={saving} onChange={e => setEditing({...editing, description: e.target.value})} /></label>
        <label><input type="checkbox" checked={editing.isRestricted} disabled={saving} onChange={e => setEditing({...editing, isRestricted: e.target.checked})} /> Ограниченная сеть</label>
        <p className="muted">Контур: {editing.contour === "SITES" ? "Объекты" : "Сотрудники"}. Адреса сетей, используемых в доступах, и VPN-пулы защищены от изменения.</p>
        {saveError && <p className="error-state" role="alert">{saveError}</p>}
        <div className="h-row"><button className="btn" disabled={saving}>{saving ? "Сохраняем…" : "Сохранить сеть"}</button><button className="btn secondary" type="button" disabled={saving} onClick={() => setEditing(null)}>Отмена</button></div>
      </form>}
      <div className="table-card" tabIndex={0} role="region" aria-label="Подсети объектов">
        <div className="table-head"><h2>Подсети объектов</h2><label><input type="checkbox" checked={onlyOnline} onChange={e => setOnlyOnline(e.target.checked)} /> Только онлайн</label></div>
        <table><thead><tr><th>Объект</th><th>Подсети за роутером</th><th>VPN IP</th><th>Подключение</th><th>Настройка</th></tr></thead>
          <tbody>{connectedSites.map(s => <tr key={s.id}><td>{s.name}</td><td className="mono">{s.lanCidr || "Подсети не указаны"}</td><td className="mono">{s.vpnIp}</td><td><span className={s.online ? "pill good" : "pill"}>{s.online ? "Онлайн" : "Не в сети"}</span></td><td><NavLink className="btn secondary" to="/sites">К объектам</NavLink></td></tr>)}</tbody>
        </table>
        {!connectedSites.length && <p className="empty">{onlyOnline ? "Сейчас нет объектов онлайн" : "Объектов с выданным VPN пока нет"}</p>}
        <p className="muted">Показаны сохранённые локальные подсети объектов. Статус подключения не подтверждает доступность каждого устройства внутри подсети.</p>
      </div>
      <div className="dash-mid">
        <div className="table-card" tabIndex={0} role="region" aria-label="Список сетей">
          <div className="table-head"><h2>Сети</h2>{canEdit&&<button className="btn" onClick={()=>{setEditing({name:'',cidr:'',contour:'EMPLOYEES',description:'',isRestricted:false});setSaveError('');setNotice('')}}>Добавить сеть</button>}</div>
          <table>
            <thead><tr><th>Имя</th><th>CIDR</th><th>Контур</th><th></th></tr></thead>
            <tbody>
              {nets.map((n) => (
                <tr key={n.id}>
                  <td>{n.name}</td>
                  <td className="mono">{n.cidr}</td>
                  <td>{n.contour === "SITES" ? "Объекты" : "Сотрудники"}</td>
                  <td>{n.isRestricted ? <span className="pill bad">ограничена</span> : null} {canEdit && <><button className="btn secondary" onClick={() => {setEditing({...n});setSaveError("");setNotice("");}} aria-label={`Редактировать сеть ${n.name}`}>Редактировать</button> <button className="btn danger" onClick={()=>setDeleting(n)} aria-label={`Удалить сеть ${n.name}`}>Удалить</button></>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="h-row"><h2>Ресурсы</h2>{canEdit&&<button className="btn" onClick={()=>setResourceDialog({resource:{name:'',host:'',port:'',kind:'SERVICE',contour:'EMPLOYEES',networkId:'',description:''},remove:false})}>Добавить ресурс</button>}</div>
          {res.map((r) => <div className="net-item" key={r.id}><span>{r.name}<small className="cell-detail">{r.contour==='SITES'?'Объекты':'Сотрудники'}</small></span><b className="mono">{r.host}{r.port ? `:${r.port}` : ""}<small className="cell-detail">{r.protocol||"Требуется переоформление доступа"}</small></b>{canEdit&&<div className="toolbar"><button className="btn secondary" aria-label={`Редактировать ресурс ${r.name}`} onClick={()=>setResourceDialog({resource:r,remove:false})}>Редактировать</button><button className="btn danger" aria-label={`Удалить ресурс ${r.name}`} onClick={()=>setResourceDialog({resource:r,remove:true})}>Удалить</button></div>}</div>)}
          {!res.length && <p className="muted">Ресурсов пока нет</p>}
        </div>
      </div>
    </>
  );
}


function Audit() {
  const [people, setPeople] = useState<any[]>([]);
  const [links, setLinks] = useState<any[]>([]);
  const [peoplePage, setPeoplePage] = useState(1);
  const [vpnPage, setVpnPage] = useState(1);
  const [totals, setTotals] = useState({people: 0, vpn: 0});
  const [actors, setActors] = useState<string[]>([]);
  const [actorNames, setActorNames] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [who, setWho] = useState("");
  const actionText: Record<string, string> = {
    login: "Вход в систему",
    wg_config_open: "Открыл ключ",
    wg_config_copy: "Скопировал ключ",
    wg_config_download: "Скачал ключ",
    vpn_up: "Ключ подключился",
    vpn_down: "Ключ отключился",
  };
  useLiveData(() => Promise.all([api.audit("people", peoplePage, who), api.audit("vpn", vpnPage)]).then(([p, v]) => {
    setPeople(p.data || []); setLinks(v.data || []);
    setActors(p.actors || []);
    setActorNames(p.actorNames || {});
    setTotals({people: p.pagination?.totalItems || 0, vpn: v.pagination?.totalItems || 0}); setErr("");
  }).catch((e) => setErr(e.message)), [peoplePage, vpnPage, who]);
  const shownPeople = who ? people.filter((a) => a.actor === who) : people;
  const pagination = (kind: "people" | "vpn", page: number, change: (page: number) => void) => (
    <nav className="journal-pages" aria-label={kind === "people" ? "Страницы действий пользователей" : "Страницы VPN-подключений"}>
      <button className="btn ghost" disabled={page <= 1} onClick={() => change(page - 1)}>Назад</button>
      <span>Страница {page} из {Math.max(1, Math.ceil(totals[kind] / 50))} · Записей: {totals[kind]}</span>
      <button className="btn ghost" disabled={page * 50 >= totals[kind]} onClick={() => change(page + 1)}>Далее</button>
    </nav>
  );
  return (
    <>
      <h1>Журнал действий</h1>
      <p className="muted">История хранится 30 дней. Более старые записи удаляются автоматически.</p>
      {err && <div className="err">{err}</div>}
      <div className="journal-split">
      <div className="table-card">
        <div className="table-head">
          <h2>Пользователи системы</h2>
          <select aria-label="Фильтр журнала по пользователю" value={who} onChange={(e) => {setWho(e.target.value);setPeoplePage(1);}} style={{ maxWidth: 280 }}>
            <option value="">Все пользователи</option>
            {actors.map((name) => <option key={name} value={name}>{actorNames[name] || name}</option>)}
          </select>
        </div>
        <p className="muted" style={{ margin: "0 14px 10px" }}>Вход, какой ключ открыли, скопировали или скачали. MAC виден, только если вход был из локальной сети.</p>
        <div className="journal-scroll" tabIndex={0} role="region" aria-label="Журнал действий пользователей">
        <table>
          <thead><tr><th>Когда</th><th>Кто</th><th>Действие</th><th>Ключ</th><th>IP</th><th>MAC</th><th>Браузер</th></tr></thead>
          <tbody>
            {shownPeople.map((a) => (
              <tr key={a.id}>
                <td>{creationDateLabel(a.createdAt)}</td>
                <td>{a.actor}</td>
                <td>{actionText[a.action] || a.action}</td>
                <td>{a.action === "login" ? "—" : (a.target || "—")}</td>
                <td className="mono">{a.ip || "—"}</td>
                <td className="mono">{a.mac || "—"}</td>
                <td>{a.browser || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!shownPeople.length && <div className="empty">{who ? "У этого пользователя записей нет" : "Записей пока нет"}</div>}
        </div>
        {pagination("people", peoplePage, setPeoplePage)}
      </div>
      <div className="table-card">
        <div className="table-head"><h2>VPN подключения</h2></div>
        <p className="muted" style={{ margin: "0 14px 10px" }}>Когда ключ пользователя или объекта подключился и когда отключился.</p>
        <div className="journal-scroll" tabIndex={0} role="region" aria-label="Журнал VPN-подключений">
        <table>
          <thead><tr><th>Когда</th><th>Тип</th><th>Кто</th><th>Событие</th><th>IP</th><th>MAC</th></tr></thead>
          <tbody>
            {links.map((a) => (
              <tr key={a.id}>
                <td>{creationDateLabel(a.createdAt)}</td>
                <td>{a.device || "—"}</td>
                <td>{a.target || a.actor || "—"}</td>
                <td>{actionText[a.action] || a.action}</td>
                <td className="mono">{a.ip || "—"}</td>
                <td className="mono">{a.mac || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!links.length && <div className="empty">Подключений пока нет</div>}
        </div>
        {pagination("vpn", vpnPage, setVpnPage)}
      </div>
      </div>
    </>
  );
}

function TotpBind({ userId, confirmed }: { userId: string; confirmed: boolean }) {
  const [on, setOn] = useState(confirmed);
  const [setup, setSetup] = useState<any>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function start(reset = false) {
    setErr("");
    setBusy(true);
    try {
      const next = await api.bindTotp(userId, reset);
      setSetup(next);
      setOn(!!next.confirmed);
    } catch (ex: any) {
      setErr(ex.message || "Не удалось подготовить 2ФА");
    } finally {
      setBusy(false);
    }
  }
  async function confirm() {
    setErr("");
    setBusy(true);
    try {
      const next = await api.confirmTotpBind(userId, code);
      setOn(!!next.totpConfirmed);
      setSetup(null);
      setCode("");
    } catch (ex: any) {
      setErr(ex.message || "Неверный код");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="span-2">
      <span className={pill(on ? "OK" : "WARNING")}>{on ? "2ФА привязана" : "2ФА не привязана"}</span>
      {!setup && (
        <button type="button" className="btn ghost" style={{ marginLeft: 8 }} disabled={busy} onClick={() => start(on)}>
          {on ? "Привязать заново" : "Привязать 2ФА"}
        </button>
      )}
      {setup && !setup.confirmed && (
        <div style={{ marginTop: 12 }}>
          <p className="muted">Отсканируйте код в приложении-аутентификаторе и введите 6 цифр.</p>
          {setup.qr && <img className="totp-qr" src={setup.qr} alt="Код для приложения" />}
          {setup.secret && <p className="mono">{setup.secret}</p>}
          <div className="toolbar">
            <input inputMode="numeric" autoComplete="one-time-code" placeholder="Код" value={code} onChange={(e) => setCode(e.target.value)} style={{ maxWidth: 140 }} />
            <button type="button" className="btn marking" disabled={busy || code.replace(/\D/g, "").length < 6} onClick={confirm}>Подтвердить</button>
            <button type="button" className="btn ghost" onClick={() => setSetup(null)}>Закрыть</button>
          </div>
        </div>
      )}
      {err && <div className="err">{err}</div>}
    </div>
  );
}

function Settings() {
  const [settingsQuery] = useSearchParams();
  const routeSection = settingsQuery.get('section');
  const [entryLink,setEntryLink]=useState('');
  const [entryOwner,setEntryOwner]=useState('');
  async function showEntry(userId:string, name:string) {
    try {
      const response=await fetch(`/api/users/${encodeURIComponent(userId)}/panel-link`,{cache:'no-store'});
      const out=await response.json();
      if(!response.ok) throw new Error(out.error?.message || out.detail || 'Нет доступа');
      setEntryLink(location.origin+out.path);setEntryOwner(name);
    } catch(error:any){setErr(error.message)}
  }
  const [staff, setStaff] = useState<any[]>([]);
  const [meEmail, setMeEmail] = useState(localStorage.getItem("kontur_email") || "");
  const [meRole, setMeRole] = useState("");
  const [err, setErr] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ fullName: "", email: "", password: "", passwordConfirm: "", role: "IT_STAFF" });
  const [edit, setEdit] = useState<any>(null);
  const isAdmin = meRole === "ADMIN";
  const section = routeSection || (isAdmin ? 'channels' : 'accounts');
  const showAccounts = section === 'accounts' && !!meRole && meRole !== 'USER' && meRole !== 'NONE';
  const loadStaff = () => showAccounts ? api.users().then((u) => setStaff((u.data || []).filter((row: any) => isStaffRole(row.role)))) : Promise.resolve();
  useLiveData(loadStaff, [showAccounts]);
  useEffect(() => {
    api.me().then((m) => {
      if (m?.email) {
        localStorage.setItem("kontur_email", m.email);
        setMeEmail(m.email);
      }
      if (m?.role) {
        localStorage.setItem("kontur_role", m.role);
        setMeRole(m.role);
      } else {
        setMeRole("NONE");
      }
    }).catch(() => setMeRole("NONE"));
  }, []);
  useEffect(() => { if (showAccounts) loadStaff().catch((e) => setErr(e.message)); }, [showAccounts]);
  if (routeSection && !['interfaces', 'channels', 'backups', 'ad', 'accounts'].includes(routeSection)) return <Navigate to="/settings" replace />;
  if (meRole && !isAdmin && section !== 'accounts') return <Navigate to="/settings" replace />;
  async function createStaff(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setOk("");
    if (form.password !== form.passwordConfirm) {
      setErr("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const out = await api.createUser({
        fullName: form.fullName,
        email: form.email.trim(),
        password: form.password,
        role: form.role,
        title: "",
        companyId: null,
        departmentId: null,
      });
      setOk(`${roleLabel(out.role)} ${out.fullName} создан. Вход по логину ${out.email} и заданному паролю.`);
      setForm({ fullName: "", email: "", password: "", passwordConfirm: "", role: form.role });
      await loadStaff();
    } catch (ex: any) {
      setErr(ex.message || "Не удалось создать учётную запись");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="settings-page">
      <header className="settings-page-head"><div className="eyebrow">Управление системой</div><h1>Настройки</h1><p className="muted">{section === 'interfaces' ? 'Сетевые карты и назначения подключений.' : section === 'channels' ? 'Скорость каналов и история измерений.' : section === 'backups' ? 'Внешнее хранилище резервных копий.' : section === 'ad' ? 'Подключение и синхронизация Active Directory.' : 'Доступ к панели управления.'}</p></header>
      {err && !edit && <div className="err" role="alert">{err}</div>}
      {ok && <div className="ok-msg" role="status">{ok}</div>}
      <div className={`settings-layout${isAdmin?'':' is-readonly'}`}>
      {isAdmin && <nav className="settings-nav" aria-label="Разделы настроек"><span className="settings-nav-caption">Разделы настроек</span>{([['interfaces','00','Сетевые интерфейсы'],['channels','01','Каналы и мониторинг'],['backups','02','Резервные копии'],['ad','03','Active Directory'],['accounts','04','Учётные записи']] as const).map(([id,index,label]) => <Link key={id} to={`/settings?section=${id}`} aria-current={section === id ? 'page' : undefined} className={section === id ? 'active' : undefined}><span aria-hidden="true">{index}</span>{label}</Link>)}<p>Каждый раздел открывается отдельно. Для новых сетевых карт укажите назначение в разделе интерфейсов.</p></nav>}
      <div className="settings-body">
      {isAdmin && section === 'interfaces' && <FirstRun settingsMode />}
      {isAdmin && (section === 'channels' || section === 'backups') && <OperationsSettings key={section} section={section} />}
      {isAdmin && section === 'ad' && <AdSettings />}
      {showAccounts && <>
      {meRole && meRole !== "ADMIN" && <p className="muted">Создавать учётные записи управления может только администратор.</p>}
      <section id="settings-management" className="settings-management" aria-labelledby="management-title">
      <div className="settings-section-head"><span className="settings-section-index" aria-hidden="true">04</span><div><h2 id="management-title">Доступ к управлению</h2><p>Учётные записи администраторов и ИТ-сотрудников.</p></div><span className="settings-tag">Записей: {staff.length}</span></div>
      {isAdmin && <form className="card form-grid settings-staff-create" onSubmit={createStaff} aria-label="Создание учётной записи управления">
        <div className="settings-form-intro span-2"><h3>Новая учётная запись</h3><p className="settings-field-help">Укажите данные для входа и назначьте роль. Пароль должен содержать не менее 8 символов.</p></div>
        <label className="field">
          <span>ФИО</span>
          <input value={form.fullName} onChange={(e) => setForm({ ...form, fullName: e.target.value })} required />
        </label>
        <label className="field">
          <span>Логин</span>
          <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} autoComplete="off" required />
        </label>
        <label className="field">
          <span>Пароль</span>
          <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="new-password" minLength={8} required />
        </label>
        <label className="field">
          <span>Пароль ещё раз</span>
          <input type="password" value={form.passwordConfirm} onChange={(e) => setForm({ ...form, passwordConfirm: e.target.value })} autoComplete="new-password" minLength={8} required />
        </label>
        <label className="field">
          <span>Роль</span>
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="ADMIN">Администратор</option>
            <option value="IT_LEAD">Руководитель ИТ</option>
            <option value="IT_STAFF">Сотрудник ИТ</option>
          </select>
        </label>
        <div className="span-2 settings-actions">
          <span className="settings-field-help">Роль определяет доступ к разделам панели.</span>
          <button className="btn marking" type="submit" disabled={busy}>{busy ? "Сохранение…" : "Добавить"}</button>
        </div>
      </form>}
      <div className="table-card settings-staff-table">
        <div className="table-head"><h2>Учётные записи управления</h2></div>
        {isAdmin && entryLink && <label className="field settings-entry-link"><span>Ссылка входа: {entryOwner}</span><input aria-label="Ссылка входа выбранной учётной записи" readOnly value={entryLink} onFocus={e=>e.target.select()} /></label>}
        <div className="table-scroll" role="region" aria-label="Учётные записи управления" tabIndex={0}>
        <table>
          <thead>
            <tr><th>ФИО</th><th>Логин</th><th>Роль</th><th></th></tr>
          </thead>
          <tbody>
            {staff.map((u) => (
              <tr key={u.id}>
                <td>
                  <div className="user-cell">
                    <div className="avatar">{initials(u.fullName)}</div>
                    <div>{u.fullName}</div>
                  </div>
                </td>
                <td>{u.email}</td>
                <td>{roleLabel(u.role)}</td>
                <td>
                  <div className="toolbar">
                    <span className={pill(accountLabel(u).pill)}>{accountLabel(u).text}</span>
                    {isAdmin && <button type="button" className="btn ghost tiny" onClick={()=>showEntry(u.id,u.fullName)}>Ссылка входа</button>}
                    {isAdmin && <button type="button" className="btn ghost tiny" onClick={() => { setErr(""); setEdit({ id: u.id, fullName: u.fullName, email: u.email, emailBefore: u.email, password: "", passwordConfirm: "", role: u.role, totpConfirmed: !!u.totpConfirmed }); }}>Изменить</button>}
                    {isAdmin && u.email !== meEmail && (
                      <>
                        {u.blocked || u.isActive === false ? (
                          <button type="button" className="btn tiny" onClick={async () => { setErr(""); try { const next = await api.unblockUser(u.id); setStaff((rows) => rows.map((row) => row.id === next.id ? { ...row, ...next } : row)); } catch (ex: any) { setErr(ex.message); } }}>Разблокировать</button>
                        ) : (
                          <button type="button" className="btn danger tiny" onClick={async () => { setErr(""); try { const next = await api.blockUser(u.id); setStaff((rows) => rows.map((row) => row.id === next.id ? { ...row, ...next } : row)); } catch (ex: any) { setErr(ex.message); } }}>Заблокировать</button>
                        )}
                        <DeleteButton tiny onError={setErr} onDelete={async () => { await api.deleteUser(u.id); setStaff((rows) => rows.filter((row) => row.id !== u.id)); }} />
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        {!staff.length && <div className="empty">Учётных записей управления нет</div>}
        <p className="settings-table-note">Создавать, изменять, блокировать и удалять учётные записи может только администратор. Свою запись заблокировать или удалить нельзя.</p>
      </div>
      {isAdmin && edit && (
        <form className="card form-grid settings-staff-edit" aria-label="Изменение учётной записи управления" onSubmit={async (e) => {
          e.preventDefault();
          setErr("");
          setOk("");
          if ((edit.password || edit.passwordConfirm) && edit.password !== edit.passwordConfirm) {
            setErr("Пароли не совпадают");
            return;
          }
          try {
            const next = await api.updateUser(edit.id, {
              fullName: edit.fullName,
              email: edit.email,
              role: edit.role,
              password: edit.password || undefined,
            });
            if (edit.emailBefore === meEmail) {
              localStorage.setItem("kontur_email", next.email);
              localStorage.setItem("kontur_name", next.fullName);
              localStorage.setItem("kontur_role", next.role);
              setMeEmail(next.email);
            }
            setStaff((rows) => rows.map((row) => row.id === next.id ? { ...row, ...next } : row));
            setEdit(null);
            setOk(`Учётная запись ${next.email} изменена.`);
          } catch (ex: any) {
            setErr(ex.message || "Не удалось изменить учётную запись");
          }
        }}>
          <h2 className="span-2">Изменение учётной записи</h2>
          {err && <div className="err span-2" role="alert">{err}</div>}
          <label className="field"><span>ФИО</span><input value={edit.fullName} onChange={(e) => setEdit({ ...edit, fullName: e.target.value })} required /></label>
          <label className="field"><span>Логин</span><input value={edit.email} onChange={(e) => setEdit({ ...edit, email: e.target.value })} required /></label>
          <label className="field"><span>Новый пароль</span><input type="password" value={edit.password} placeholder="Оставьте пустым, чтобы не менять" minLength={edit.password ? 8 : undefined} onChange={(e) => setEdit({ ...edit, password: e.target.value })} autoComplete="new-password" /></label>
          <label className="field"><span>Пароль ещё раз</span><input type="password" value={edit.passwordConfirm} placeholder="Повторите новый пароль" minLength={edit.passwordConfirm ? 8 : undefined} onChange={(e) => setEdit({ ...edit, passwordConfirm: e.target.value })} autoComplete="new-password" /></label>
          <label className="field">
            <span>Роль</span>
            <select value={edit.role} onChange={(e) => setEdit({ ...edit, role: e.target.value })}>
              <option value="ADMIN">Администратор</option>
              <option value="IT_LEAD">Руководитель ИТ</option>
              <option value="IT_STAFF">Сотрудник ИТ</option>
            </select>
          </label>
          <TotpBind key={edit.id} userId={edit.id} confirmed={!!edit.totpConfirmed} />
          <div className="span-2 toolbar">
            <button className="btn marking" type="submit">Сохранить</button>
            <button className="btn ghost" type="button" onClick={() => setEdit(null)}>Отмена</button>
          </div>
        </form>
      )}
      </section>
      </>}
      </div>
      </div>
    </div>
  );
}

function Guard({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}

export function App() {
  const documents = useDocumentViewer();
  const openDocument = useRef(documents.open);
  openDocument.current = documents.open;
  useEffect(() => {
    const preview = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      if (typeof detail?.id !== "string" || !detail.id) return;
      void openDocument.current(detail.id, typeof detail.filename === "string" ? detail.filename : "Служебная записка.pdf");
    };
    window.addEventListener("vpn:preview-document", preview);
    return () => window.removeEventListener("vpn:preview-document", preview);
  }, []);
  return (
    <>
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Guard><Home /></Guard>} />
      <Route path="/users" element={<Guard><Users /></Guard>} />
      <Route path="/users/:id" element={<Guard><UserCard /></Guard>} />
      <Route path="/devices" element={<Guard><Devices /></Guard>} />
      <Route path="/devices/:id" element={<Guard><DeviceCard /></Guard>} />
      <Route path="/connections" element={<Guard><Connections /></Guard>} />
      <Route path="/sites" element={<Guard><Sites /></Guard>} />
      <Route path="/networks" element={<Guard><Networks /></Guard>} />
      <Route path="/requests" element={<Navigate to="/approved" replace />} />
      <Route path="/approved" element={<Guard><div /></Guard>} />
      <Route path="/incidents" element={<Navigate to="/" replace />} />
      <Route path="/audit" element={<Guard><Audit /></Guard>} />
      <Route path="/stats" element={<Navigate to="/" replace />} />
      <Route path="/settings" element={<Guard><Settings /></Guard>} />
    </Routes>
    {documents.view}
    </>
  );
}
