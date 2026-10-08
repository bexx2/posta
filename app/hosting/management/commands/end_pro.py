"""İade/iptal sonrası: Pro'yu bitir, ücretsiz plana indir (fazla kutular askıya alınır). Parayı iyzico panelinden iade ettikten SONRA çalıştır."""
from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from hosting import services


class Command(BaseCommand):
    help = "end_pro <user_email>"

    def add_arguments(self, p):
        p.add_argument("email")

    def handle(self, *a, email, **kw):
        u = User.objects.filter(email=email.strip().lower()).first()
        if not u:
            raise CommandError("kullanıcı yok")
        errs = services.downgrade_to_free(u, reason="refunded")
        self.stdout.write(f"{u.email}: ücretsiz plana indi. hatalar: {errs}")
