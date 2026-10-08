export function ownerLabel(user) {
  const name = String(user.fullName || '').trim() || 'Без ФИО';
  const login = String(user.email || '').trim();
  return `${name} · ${login || `ID: ${user.id}`}`;
}
