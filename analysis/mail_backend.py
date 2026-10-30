import smtplib

from django.conf import settings
from django.core.mail.backends.smtp import EmailBackend as SMTPBackend
from django.core.mail.message import sanitize_address


class PartialDelivery(smtplib.SMTPException):
    """At least one intended recipient was refused; do not resend automatically."""


class EmailBackend(SMTPBackend):
    def _send(self, email_message):
        encoding = email_message.encoding or settings.DEFAULT_CHARSET
        refused = self.connection.sendmail(
            sanitize_address(email_message.from_email, encoding),
            [sanitize_address(address, encoding) for address in email_message.recipients()],
            email_message.message().as_bytes(linesep="\r\n"),
        )
        if refused:
            raise PartialDelivery()
        return True
