from pathlib import Path


def memory_status():
    """Linux available memory includes reclaimable cache, not just free pages."""
    try:
        values = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            if key in ('MemTotal', 'MemAvailable'):
                values[key] = int(value.split()[0]) * 1024
        total = values['MemTotal']
        available = values['MemAvailable']
        if total <= 0 or not 0 <= available <= total:
            return None
        used = total - available
        return {'totalBytes':total, 'usedBytes':used, 'availableBytes':available, 'usedPercent':round(used / total * 100, 1)}
    except (OSError, ValueError, KeyError, IndexError):
        return None
