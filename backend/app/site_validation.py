import ipaddress
from fastapi import HTTPException


def site_lan(value: str) -> str:
    parts = [p.strip() for p in (value or '').split(',')]
    if not parts or len(parts) > 16 or any(not p for p in parts):
        raise HTTPException(422, 'Укажите от 1 до 16 LAN-подсетей через запятую, например 192.168.75.0/24')
    networks = []
    private = [ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=True)
        except ValueError:
            raise HTTPException(422, f'Некорректная LAN-подсеть «{part[:100]}». Укажите адрес сети и маску, например 192.168.75.0/24. Проверьте лишние точки и адрес сети.')
        if '/' not in part or net.version != 4 or not any(net.subnet_of(n) for n in private):
            raise HTTPException(422, 'Нужна локальная IPv4-подсеть с маской, например 192.168.75.0/24')
        if net in networks:
            continue
        if any(net.overlaps(n) for n in networks):
            raise HTTPException(422, 'LAN-подсети объекта пересекаются между собой')
        networks.append(net)
    return ', '.join(map(str, networks))
