from datetime import datetime, timedelta
from threading import RLock
from sqlalchemy.orm import joinedload

from .models import WireGuardPeer

ONLINE_SECONDS = 25
_observations = {}
_lock = RLock()


def reset_observations():
    with _lock:
        _observations.clear()


def observe_peer(key, rx, handshake, now):
    with _lock:
        previous = _observations.get(key)
        seen = previous[2] if previous else None
        if previous and rx > previous[0]:
            seen = now
        elif handshake and (not previous or handshake > previous[1]):
            stamp = datetime.utcfromtimestamp(handshake)
            if 0 <= (now - stamp).total_seconds() < ONLINE_SECONDS:
                seen = stamp
        _observations[key] = (rx, handshake, seen)


def peer_online(peer: WireGuardPeer | None, now=None) -> bool:
    if not peer or not peer.enabled:
        return False
    with _lock:
        observation = _observations.get(peer.public_key)
    seen = observation[2] if observation else None
    return bool(seen and 0 <= ((now or datetime.utcnow()) - seen).total_seconds() < ONLINE_SECONDS)


def sample_presence(db):
    # One worker owns this short-lived cache. After restart we wait for fresh RX,
    # rather than treating historical byte counters as proof of connectivity.
    from . import wireguard
    from .models import Contour
    from .engine import _note_link
    rows = [row for contour in (Contour.EMPLOYEES, Contour.SITES) for row in wireguard.dump(contour)]
    now = datetime.utcnow()
    keys = {row['public_key'] for row in rows}
    with _lock:
        for key in list(_observations):
            if key not in keys:
                del _observations[key]
    for row in rows:
        observe_peer(row['public_key'], row.get('rx') or 0, row.get('latest_handshake') or 0, now)
    # Do not wait behind lifecycle operations; skipped locked peers are retried
    # on the next sample. Link state and its audit entry commit together once.
    peers = db.query(WireGuardPeer).options(joinedload(WireGuardPeer.device)).with_for_update(of=WireGuardPeer, skip_locked=True).all()
    for peer in peers:
        _note_link(db, peer, peer.device, peer_online(peer, now), peer.endpoint or '', commit=False)
    db.commit()
