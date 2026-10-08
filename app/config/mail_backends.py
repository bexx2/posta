"""
Loopback Mailcow submission (127.0.0.1:587) için e-posta backend'i.

Mailcow'un submission dinleyicisi self-signed sertifika sunar; Django'nun smtp
backend'i STARTTLS'te sertifikayı DOĞRULAR → loopback'te CERTIFICATE_VERIFY_FAILED
ile doğrulama/parola-sıfırlama mailleri sessizce gitmez. Bağlantı loopback'te
olduğundan MITM riski yok: STARTTLS şifrelemesi korunur, yalnız sertifika
doğrulaması kapatılır. Uzak bir host'a geçilirse Django varsayılanı (tam doğrulama)
otomatik geri gelir (aşağıdaki guard). Desen: HeyvAnka/HeyvAql/mail_backends.py.
"""
import ssl

from django.core.mail.backends.smtp import EmailBackend as _SMTPEmailBackend


class LoopbackTLSEmailBackend(_SMTPEmailBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.host in ("127.0.0.1", "localhost", "::1"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.ssl_context = ctx
