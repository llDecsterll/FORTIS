export function getToken() {
  return document.cookie.split('; ').find(v => v.startsWith('fortis_session_hint='))?.split('=')[1] || '';
}

export function setToken(_token: string) {
  // The credential is an HttpOnly cookie. This value is only a UI hint.
  localStorage.removeItem('kontur_token');
}

export function clearToken() {
  localStorage.removeItem('kontur_token');
  document.cookie = 'fortis_session_hint=; Max-Age=0; Path=/; SameSite=Strict';
  document.cookie = 'fortis_csrf=; Max-Age=0; Path=/; SameSite=Strict';
}

export function saveTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();

  if (!(init.body instanceof FormData) && !headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401 && path !== '/api/auth/login' && path !== '/api/auth/totp') {
    window.dispatchEvent(new CustomEvent('vpn:unauthorized', { detail: { token } }));
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = data?.error?.message || data?.detail || res.statusText;
    const error = new Error(typeof message === "string" ? message : "Ошибка запроса") as Error & { retryAfter?: number };
    const retryAfter = Number(data?.error?.retryAfter || 0);
    if (retryAfter > 0) error.retryAfter = retryAfter;
    throw error;
  }
  return data as T;
}

export const api = {
  approvalSummary: () => req<{pending:number;pendingIds:string[]}>('/api/approvals/summary'),
  operations: () => req<any>('/api/settings/operations'),
  channelStatus: () => req<any>('/api/settings/channels/status'),
  backupStatus: () => req<any>('/api/settings/backups/status'),
  saveOperations: (body: any) => req<any>('/api/settings/operations', {method: 'PUT', body: JSON.stringify(body)}),
  login: (email: string, password: string) =>
    req<{ token: string; role: string; fullName: string; email: string; totpRequired?: boolean; totpSetup?: boolean; challenge?: string; qr?: string; secret?: string; blocked?: boolean; blockedBy?: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  confirmTotp: (challenge: string, code: string) =>
    req<{ token: string; role: string; fullName: string; email: string; blocked?: boolean; blockedBy?: string }>("/api/auth/totp", {
      method: "POST",
      body: JSON.stringify({ challenge, code }),
    }),
  me: () => req<any>("/api/auth/me"),
  logout: () => req<{ok:boolean}>("/api/auth/logout", {method: "POST"}),
  adSettings: () => req<any>("/api/settings/ad"),
  saveAd: (body: any) => req<any>("/api/settings/ad", { method: "PUT", body: JSON.stringify(body) }),
  syncAd: () => req<any>("/api/settings/ad/sync", { method: "POST" }),
  checkAd: (id: string) => req<any>(`/api/settings/ad/${encodeURIComponent(id)}/check`, {method: "POST"}),
  adDeletion: (id: string) => req<any>(`/api/settings/ad/${encodeURIComponent(id)}/deletion`),
  deleteAd: (id: string, confirmation: string, revision: string) => req<any>(`/api/settings/ad/${encodeURIComponent(id)}`, {method: "DELETE", body: JSON.stringify({confirmation, revision})}),
  dashboard: () => req<any>("/api/dashboard"),
  users: (q = "") => req<any>(`/api/users?q=${encodeURIComponent(q)}`),
  user: (id: string) => req<any>(`/api/users/${id}`),
  createUser: (body: any) => req<any>("/api/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: any) => req<any>(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  bindTotp: (id: string, reset = false) => req<any>(`/api/users/${id}/totp`, { method: "POST", body: JSON.stringify({ reset }) }),
  confirmTotpBind: (id: string, code: string) => req<any>(`/api/users/${id}/totp/confirm`, { method: "POST", body: JSON.stringify({ code }) }),
  createEmployee: (body: FormData) => req<any>("/api/users/employee", { method: "POST", body }),
  documentBlob: async (id: string) => {
    const token = getToken();
    const res = await fetch(`/api/documents/${id}`, { credentials: "same-origin" });
    if (res.status === 401) window.dispatchEvent(new CustomEvent('vpn:unauthorized', { detail: { token } }));
    if (!res.ok) throw new Error("Не удалось открыть документ");
    return res.blob();
  },
  downloadDocument: async (id: string, filename: string) => {
    const blob = await api.documentBlob(id);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "memo.pdf";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  createCompany: (name: string) => req<any>("/api/companies", { method: "POST", body: JSON.stringify({ name }) }),
  createDepartment: (name: string, companyId?: string) =>
    req<any>("/api/departments", { method: "POST", body: JSON.stringify({ name, companyId }) }),
  devices: (contour?: string) => req<any>(`/api/devices${contour ? `?contour=${contour}` : ""}`),
  device: (id: string) => req<any>(`/api/devices/${id}`),
  blockDevice: (id: string) => req<any>(`/api/devices/${id}/block`, { method: "POST" }),
  unblockDevice: (id: string) => req<any>(`/api/devices/${id}/unblock`, { method: "POST" }),
  revokeDevice: (id: string) => req<any>(`/api/devices/${id}/revoke`, { method: "POST" }),
  sites: () => req<any>("/api/sites"),
  createSite: (body: any) => req<any>("/api/sites", { method: "POST", body: JSON.stringify(body) }),
  requests: () => req<any>("/api/requests"),
  createRequest: (body: any) => req<any>("/api/requests", { method: "POST", body: JSON.stringify(body) }),
  approve: (id: string) => req<any>(`/api/requests/${id}/approve`, { method: "POST" }),
  reject: (id: string) => req<any>(`/api/requests/${id}/reject`, { method: "POST" }),
  issue: (id: string) => req<any>(`/api/requests/${id}/issue`, { method: "POST" }),
  networks: (contour?: string) => req<any>(`/api/networks${contour ? `?contour=${contour}` : ""}`),
  pingNetwork: (ip: string) => req<any>('/api/networks/ping', { method: 'POST', body: JSON.stringify({ ip }) }),
  updateNetwork: (id: string, body: any) => req<any>(`/api/networks/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  networkDeletion: (id: string) => req<any>(`/api/networks/${encodeURIComponent(id)}/deletion`),
  deleteNetwork: (id: string, confirmation: string, revision: string) => req<any>(`/api/networks/${encodeURIComponent(id)}?confirmation=${encodeURIComponent(confirmation)}&revision=${encodeURIComponent(revision)}`, {method:'DELETE'}),
  resources: (contour?: string) => req<any>(`/api/resources${contour ? `?contour=${contour}` : ""}`),
  siteLinks: () => req<any>('/api/site-links'),
  createSiteLink: (body:any) => req<any>('/api/site-links',{method:'POST',body:JSON.stringify(body)}),
  toggleSiteLink: (id:string,enabled:boolean) => req<any>(`/api/site-links/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({enabled})}),
  deleteSiteLink: (id:string) => req<any>(`/api/site-links/${encodeURIComponent(id)}`,{method:'DELETE'}),
  createNetwork: (body: any) => req<any>("/api/networks", { method: "POST", body: JSON.stringify(body) }),
  createResource: (body: any) => req<any>("/api/resources", { method: "POST", body: JSON.stringify(body) }),
  updateResource: (id:string,body:any) => req<any>(`/api/resources/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify(body)}),
  deleteResource: (id:string,name:string) => req<any>(`/api/resources/${encodeURIComponent(id)}?confirmation=${encodeURIComponent(name)}`,{method:'DELETE'}),
  incidents: (status: 'current' | 'archived' = 'current', page = 1) => req<any>(`/api/incidents?status=${status}&page=${page}&pageSize=50`),
  archiveIncident: (id: string, archived: boolean) => req<any>(`/api/incidents/${encodeURIComponent(id)}/archive`, {method:'PUT', body:JSON.stringify({archived})}),
  audit: (kind = "all", page = 1, actor = "") => req<any>(`/api/audit?kind=${kind}&page=${page}&pageSize=50&actor=${encodeURIComponent(actor)}`),
  noteKeyCopy: (body: { userId?: string; siteId?: string; action?: "open" | "copy" | "download" }) => req<any>("/api/audit/key-copy", { method: "POST", body: JSON.stringify(body) }),
  connections: () => req<any>("/api/connections"),
  settings: () => req<any>("/api/settings"),
  saveSettings: (body: any) => req<any>("/api/settings", { method: "PUT", body: JSON.stringify(body) }),
  companies: () => req<any>("/api/companies"),
  departments: () => req<any>("/api/departments"),
  userVpn: (id: string) => req<any>(`/api/users/${id}/vpn`),
  siteVpn: (id: string) => req<any>(`/api/sites/${id}/vpn`),
  deleteUser: (id: string) => req<any>(`/api/users/${id}`, { method: "DELETE" }),
  deleteSite: (id: string) => req<any>(`/api/sites/${id}`, { method: "DELETE" }),
  suspendSite: (id: string) => req<any>(`/api/sites/${id}/suspend`, { method: "POST" }),
  resumeSite: (id: string) => req<any>(`/api/sites/${id}/resume`, { method: "POST" }),
  disconnectSite: (id: string) => req<any>(`/api/sites/${id}/disconnect`, { method: "POST" }),
  connectSite: (id: string) => req<any>(`/api/sites/${id}/connect`, { method: "POST" }),
  unblockSite: (id: string) => req<any>(`/api/sites/${id}/unblock`, { method: "POST" }),
  blockUser: (id: string) => req<any>(`/api/users/${id}/block`, { method: "POST" }),
  unblockUser: (id: string) => req<any>(`/api/users/${id}/unblock`, { method: "POST" }),
  suspendUser: (id: string) => req<any>(`/api/users/${id}/suspend`, { method: "POST" }),
  resumeUser: (id: string) => req<any>(`/api/users/${id}/resume`, { method: "POST" }),
};
