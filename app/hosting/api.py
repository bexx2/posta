"""REST API (v1). Hata biçimi: {"error": {"code", "message"}}. Anahtar kapsamı (scope) her uçta zorunlu; oturum açmış kullanıcı tüm kapsamlara sahiptir."""
from rest_framework import serializers, status
from rest_framework.exceptions import APIException
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView, exception_handler as drf_handler

from . import services
from .models import ApiKey, Domain, Mailbox


def exception_handler(exc, context):
    if isinstance(exc, services.ServiceError):
        return Response({"error": {"code": exc.code, "message": exc.message}}, status=exc.http)
    resp = drf_handler(exc, context)
    if resp is not None and "error" not in (resp.data if isinstance(resp.data, dict) else {}):
        detail = resp.data.get("detail") if isinstance(resp.data, dict) else None
        resp.data = {"error": {"code": getattr(exc, "default_code", "error"), "message": str(detail or resp.data)}}
    return resp


class Scope(BasePermission):
    """Görünümde `scopes = {"GET": "domains:read", "POST": "domains:write", ...}`."""
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if not isinstance(request.auth, ApiKey):          # oturum
            return True
        need = getattr(view, "scopes", {}).get(request.method)
        return bool(need) and request.auth.has_scope(need)


class SessionOnly(BasePermission):
    """Anahtar yönetimi: API anahtarıyla başka anahtar üretilemez/silinemez."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and not isinstance(request.auth, ApiKey))


def domain_json(d: Domain):
    return {"id": d.id, "name": d.name, "status": d.status, "verified_at": d.verified_at, "created_at": d.created_at,
            "dns": {"ownership_txt": d.txt_record, "mx": {"name": d.name, "type": "MX", "value": f"10 {_mx()}"},
                    "dkim": ({"name": f"{d.dkim_selector}._domainkey.{d.name}", "type": "TXT", "value": d.dkim_txt} if d.dkim_txt else None)},
            "last_check": d.last_check, "last_check_at": d.last_check_at}


def _mx():
    from django.conf import settings
    return settings.MX_TARGET


def mailbox_json(m: Mailbox):
    return {"id": m.id, "address": m.address, "quota_mb": m.quota_mb, "status": m.status, "created_at": m.created_at}


class DomainList(APIView):
    permission_classes = [Scope]
    scopes = {"GET": "domains:read", "POST": "domains:write"}

    def get(self, request):
        return Response([domain_json(d) for d in Domain.objects.filter(owner=request.user).order_by("id")])

    def post(self, request):
        d = services.add_domain(request.user, str(request.data.get("name", "")))
        return Response(domain_json(d), status=status.HTTP_201_CREATED)


def _domain(request, pk):
    d = Domain.objects.filter(pk=pk, owner=request.user).first()
    if not d:
        raise services.ServiceError("not_found", "Domain not found.", 404)
    return d


class DomainDetail(APIView):
    permission_classes = [Scope]
    scopes = {"GET": "domains:read", "DELETE": "domains:write"}

    def get(self, request, pk):
        return Response(domain_json(_domain(request, pk)))

    def delete(self, request, pk):
        services.delete_domain(request.user, _domain(request, pk))
        return Response(status=status.HTTP_204_NO_CONTENT)


class DomainVerify(APIView):
    permission_classes = [Scope]
    scopes = {"POST": "domains:write"}

    def post(self, request, pk):
        d = services.verify_domain(request.user, _domain(request, pk))
        return Response(domain_json(d))


class MailboxList(APIView):
    permission_classes = [Scope]
    scopes = {"GET": "mailboxes:read", "POST": "mailboxes:write"}

    def get(self, request):
        qs = Mailbox.objects.filter(domain__owner=request.user).order_by("id")
        return Response([mailbox_json(m) for m in qs])

    def post(self, request):
        d = _domain(request, request.data.get("domain_id"))
        m = services.create_mailbox(request.user, d, str(request.data.get("local_part", "")), str(request.data.get("password", "")))
        return Response(mailbox_json(m), status=status.HTTP_201_CREATED)


class MailboxDetail(APIView):
    permission_classes = [Scope]
    scopes = {"DELETE": "mailboxes:write"}

    def delete(self, request, pk):
        mb = Mailbox.objects.select_related("domain").filter(pk=pk, domain__owner=request.user).first()
        if not mb:
            raise services.ServiceError("not_found", "Mailbox not found.", 404)
        services.delete_mailbox(request.user, mb)
        return Response(status=status.HTTP_204_NO_CONTENT)


class KeyList(APIView):
    permission_classes = [SessionOnly]

    def get(self, request):
        keys = ApiKey.objects.filter(owner=request.user, revoked_at__isnull=True).order_by("id")
        return Response([{"id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scopes.split(","),
                          "created_at": k.created_at, "last_used_at": k.last_used_at} for k in keys])

    def post(self, request):
        scopes = request.data.get("scopes") or []
        if not isinstance(scopes, list):
            raise services.ServiceError("invalid_scopes", "scopes must be a list.")
        key, full = services.create_api_key(request.user, str(request.data.get("name", "")), scopes)
        return Response({"id": key.id, "name": key.name, "prefix": key.prefix, "scopes": scopes, "key": full,
                         "note": "Store this key now. It is shown only once."}, status=status.HTTP_201_CREATED)


class KeyDetail(APIView):
    permission_classes = [SessionOnly]

    def delete(self, request, pk):
        key = ApiKey.objects.filter(pk=pk, owner=request.user, revoked_at__isnull=True).first()
        if not key:
            raise services.ServiceError("not_found", "API key not found.", 404)
        services.revoke_api_key(request.user, key)
        return Response(status=status.HTTP_204_NO_CONTENT)


class Usage(APIView):
    permission_classes = [Scope]
    scopes = {"GET": "domains:read"}

    def get(self, request):
        m = services.membership(request.user)
        p = m.plan
        return Response({"plan": p.slug, "limits": {"domains": p.max_domains, "mailboxes_per_domain": p.max_mailboxes_per_domain,
                                                    "mailbox_quota_mb": p.mailbox_quota_mb, "daily_send_limit": p.daily_send_limit},
                         "usage": {"domains": Domain.objects.filter(owner=request.user).count(),
                                   "mailboxes": Mailbox.objects.filter(domain__owner=request.user).count()}})
