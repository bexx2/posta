from django.conf import settings


def get_backend():
    name = settings.MAIL_BACKEND
    if name == "mailcow":
        from .mailcow import MailcowBackend
        return MailcowBackend(settings.MAILCOW_API_URL, settings.MAILCOW_API_KEY)
    from .dryrun import DryRunBackend
    return DryRunBackend.instance()
