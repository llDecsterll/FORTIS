"""Widen cumulative traffic counters without resetting stored values."""
from sqlalchemy import text


def migrate_traffic_counters(conn):
    # Fixed identifiers only. Repeated startup must not rewrite already migrated tables.
    for table in ('wireguard_peers', 'traffic_samples'):
        columns = conn.execute(text(
            "SELECT attname FROM pg_attribute "
            "WHERE attrelid = to_regclass(:table) AND NOT attisdropped "
            "AND attname IN ('rx_bytes', 'tx_bytes') "
            "AND atttypid = 'integer'::regtype"
        ), {'table': table}).scalars().all()
        if columns:
            changes = ', '.join(f'ALTER COLUMN {column} TYPE BIGINT' for column in columns)
            conn.execute(text(f'ALTER TABLE {table} {changes}'))
