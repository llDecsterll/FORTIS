from datetime import datetime


def connection_members(peers, online, now=None):
    now = now or datetime.utcnow()
    groups = {}
    for peer in peers:
        d = peer.device
        if not d:
            continue
        status = getattr(d.status, 'value', d.status)
        if status == 'PENDING' or d.block_reason in ('Ожидает согласования СБ', 'Отклонено службой безопасности'):
            continue
        blocked = (not peer.enabled or status in ('BLOCKED','REVOKED','EXPIRED')
                   or (d.access_until is not None and d.access_until <= now)
                   or (not d.site_id and d.user is not None and not d.user.is_active))
        state = 'blocked' if blocked else ('online' if online(peer) else 'offline')
        key = ('site',d.site_id) if d.site_id else ('user',d.user_id or d.id)
        priority={'blocked':0,'offline':1,'online':2}
        if key not in groups or priority[state]>priority[groups[key][1]]:
            groups[key]=(peer,state)
    return list(groups.values())


def connection_counts(peers, online, now=None):
    counts = dict(online=0,offline=0,blocked=0)
    for peer,state in connection_members(peers,online,now):
        counts[state] += 1
    return counts
