"""Email notifications over SMTP."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled"))

    def send(self, subject: str, body: str) -> bool:
        if not self.enabled:
            log.info("Email disabled; would have sent: %s", subject)
            return False
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = c.get("from") or c.get("username")
        msg["To"] = ", ".join(c["to"])
        msg.set_content(body)

        try:
            ctx = ssl.create_default_context()
            if c["security"] == "ssl":
                server = smtplib.SMTP_SSL(c["smtp_host"], int(c["smtp_port"]), context=ctx, timeout=30)
            else:
                server = smtplib.SMTP(c["smtp_host"], int(c["smtp_port"]), timeout=30)
            with server:
                if c["security"] == "starttls":
                    server.starttls(context=ctx)
                if c.get("username"):
                    server.login(c["username"], c["password"])
                server.send_message(msg)
            log.info("Sent email: %s", subject)
            return True
        except (smtplib.SMTPException, OSError) as e:
            log.error("Failed to send email %r: %s", subject, e)
            return False
