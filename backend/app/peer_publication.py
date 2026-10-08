"""Serialize WireGuard publication with runtime cleanup across workers."""
from sqlalchemy import text
from .models import WireGuardPeer


def lock_peer_publication(db, contour, public_key):
    if db.get_bind().dialect.name == 'postgresql':
        # Transaction-scoped: also released on rollback/process failure. No keys
        # or credentials are persisted. Hash collisions only serialize extra work.
        db.execute(text('SELECT pg_advisory_xact_lock(73120, hashtext(:key))'),
                   {'key': public_key})


def try_lock_peer_publication(db, contour, public_key):
    if db.get_bind().dialect.name != 'postgresql':
        return True
    # The watchdog may already hold a peer row lock. Never wait for a
    # publisher that might be waiting for that row; release it and retry later.
    return bool(db.execute(text('SELECT pg_try_advisory_xact_lock(73120, hashtext(:key))'),
                           {'key': public_key}).scalar())


def recheck_peer_publication(db, contour, public_key):
    lock_peer_publication(db, contour, public_key)
    # PostgreSQL READ COMMITTED gets a fresh snapshot after the publisher commits.
    return (db.query(WireGuardPeer)
            .filter(WireGuardPeer.public_key == public_key, WireGuardPeer.contour == contour)
            .with_for_update().one_or_none())
