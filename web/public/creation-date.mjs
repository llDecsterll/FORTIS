// Legacy API timestamps without an offset are stored in UTC.
export function creationDateLabel(value) {
  if (typeof value !== 'string' || !value.trim()) return '—';
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`;
  const date = new Date(normalized);
  if (!Number.isFinite(date.getTime())) return '—';
  return `${date.toLocaleString('ru-RU', {timeZone:'Europe/Moscow', year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'})} МСК`;
}
