from datetime import datetime, timezone
from fastapi import HTTPException


def future_access_until(value, *, stored=False):
    if not value:
        raise HTTPException(422, "Укажите дату и время окончания VPN-доступа")
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None and not stored:
            raise ValueError("timezone required")
        if result.tzinfo is not None:
            result = result.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError):
        raise HTTPException(422, "Укажите корректную дату и время с часовым поясом")
    if result <= datetime.utcnow():
        raise HTTPException(422, "Срок VPN-доступа должен быть в будущем. Подайте новую заявку")
    return result
