export function vpnCountdown(value, now = Date.now()) {
  if (typeof value !== 'string' || !value) return 'Срок не указан';
  const deadline = Date.parse(/(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`);
  if (!Number.isFinite(deadline)) return 'Срок не указан';
  const remaining = Math.ceil((deadline - now) / 1000);
  if (remaining <= 0) return 'Срок истёк';
  const days = Math.floor(remaining / 86400);
  const time = [Math.floor(remaining % 86400 / 3600), Math.floor(remaining % 3600 / 60), remaining % 60].map(n => String(n).padStart(2, '0')).join(':');
  return `Осталось: ${days ? `${days} д. ` : ''}${time}`;
}
