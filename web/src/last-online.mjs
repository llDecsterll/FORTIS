export function lastOnlineLabel(value, online = false) {
  if (online) return 'Сейчас в сети';
  if (!value) return 'Подключений не было';
  // The API serializes naive UTC timestamps; never interpret them as browser-local.
  const stamp = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`;
  const date = new Date(stamp);
  if (!Number.isFinite(date.getTime())) return 'Нет данных';
  return `${new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }).format(date)} МСК`;
}
