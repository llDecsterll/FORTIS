"""Visibility from the last complete GG_VPN membership snapshot, not VPN keys."""
import json

from sqlalchemy import select

from .models import Role, Setting, User

KEY = "employee_gg_vpn_membership"


def snapshots(db):
    setting = db.get(Setting, KEY)
    return json.loads(setting.value) if setting else {}


def is_group_source(source):
    return source.get('baseDn', '').strip().casefold().startswith('cn=gg_vpn,')


def save_members(db, source_id, guids):
    state = snapshots(db)
    state[source_id] = sorted(guids)
    row = db.get(Setting, KEY)
    if row is None:
        row = Setting(key=KEY, value='{}')
        db.add(row)
    row.value = json.dumps(state)


def excluded_ids(db):
    state = snapshots(db)
    if not state:  # Bootstrap only; an unsuccessful LDAP read must not empty lists.
        return []
    all_guids = {guid for members in state.values() for guid in members}
    users = db.scalars(select(User).where(User.role == Role.USER))
    # Manual accounts are explicitly created in the panel and have no AD identity.
    # An AD-linked account remains group-controlled even if its GUID is incomplete.
    return [u.id for u in users if (u.ad_guid or u.ad_source) and
            u.ad_guid not in (state.get(u.ad_source, []) if u.ad_source else all_guids)]
