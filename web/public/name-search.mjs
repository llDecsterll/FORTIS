// Match names locally; never send a request for every character typed.
const normalizeName = value => String(value ?? '').normalize('NFKC').toLocaleLowerCase('ru-RU').replace(/ё/g, 'е').trim();

export function matchesName(name, query) {
  const normalizedName = normalizeName(name);
  return normalizeName(query).split(/\s+/).filter(Boolean).every(part => normalizedName.includes(part));
}

export function matchesEmployee(employee, query) {
  return matchesName([employee?.fullName, employee?.vpnIp].filter(Boolean).join(' '), query);
}
