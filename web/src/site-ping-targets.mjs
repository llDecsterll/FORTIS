export function ipv4Number(value) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  if (parts.some((n, i) => n > 255 || String(n) !== value.split('.')[i])) return null;
  return parts.reduce((n, part) => n * 256 + part, 0);
}

export function lanHostAllowed(ip, cidrs) {
  const host = ipv4Number(ip.trim());
  if (host === null) return false;
  return String(cidrs || '').split(',').some(raw => {
    const [address, prefixText] = raw.trim().split('/');
    const base = ipv4Number(address || '');
    if (base === null || !/^\d{1,2}$/.test(prefixText || '')) return false;
    const prefix = Number(prefixText);
    if (prefix < 1 || prefix > 32) return false;
    const size = 2 ** (32 - prefix), network = Math.floor(base / size) * size;
    return host >= network && host < network + size &&
      (prefix >= 31 || (host !== network && host !== network + size - 1));
  });
}
