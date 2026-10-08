import json
import logging
import smtplib
from email.message import EmailMessage
from urllib.request import Request, urlopen

from .config import settings

logger = logging.getLogger(__name__)


def _delivery_failed(channel: str, exc: Exception) -> None:
    # Exception text can contain SMTP credentials or a Telegram token in a URL.
    logger.warning("Notification delivery failed: channel=%s error_type=%s", channel, type(exc).__name__)


def notify(title: str, body: str, *, critical: bool = False) -> None:
    text = f"{title}\n\n{body}"
    if settings.smtp_host and settings.security_notify_email:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[FORTIS] {title}"
            msg["From"] = settings.smtp_from
            msg["To"] = settings.security_notify_email
            msg.set_content(text)
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=8) as smtp:
                smtp.starttls()
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
        except Exception as exc:
            _delivery_failed("smtp", exc)
    if settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            payload = json.dumps(
                {"chat_id": settings.telegram_chat_id, "text": f"{'🚨' if critical else 'ℹ'} {text}"}
            ).encode()
            req = Request(url, data=payload, headers={"Content-Type": "application/json"})
            urlopen(req, timeout=8).read()
        except Exception as exc:
            _delivery_failed("telegram", exc)
    if settings.webhook_url:
        try:
            payload = json.dumps({"title": title, "body": body, "critical": critical, "source": "kontur"}).encode()
            req = Request(settings.webhook_url, data=payload, headers={"Content-Type": "application/json"})
            urlopen(req, timeout=8).read()
        except Exception as exc:
            _delivery_failed("webhook", exc)
