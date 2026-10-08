// Connection presence is independent of permission: offline is not blocked.
export function employeeVpnState(user, now = Date.now()) {
  const until = user.accessUntil;
  const expired = Boolean(until && new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(until) ? until : `${until}Z`).getTime() <= now);
  const blocked = Boolean(user.blocked || user.isActive === false || user.suspended ||
    ['BLOCKED','EXPIRED','REVOKED'].includes(user.status) || user.vpnEnabled === false || expired);
  let reason = '';
  if (blocked) reason = user.blockReason?.trim() ||
    (expired || user.status === 'EXPIRED' ? 'Срок VPN-доступа истёк' :
     user.status === 'REVOKED' ? 'VPN-ключ отозван' :
     user.suspended ? 'VPN-доступ приостановлен; причина не указана' :
     user.blocked || user.isActive === false ? 'Учётная запись заблокирована; причина не указана' :
     'VPN-доступ отключён; причина не указана');
  return {blocked, reason};
}
