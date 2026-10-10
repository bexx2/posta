class RealIPMiddleware:
    """gunicorn yalnız 127.0.0.1'e bağlı; tek istemcisi Caddy ve Caddy X-Real-IP'yi HER istekte {remote_host} ile yazar (istemcinin
    gönderdiğini ezer). REMOTE_ADDR'i buna çevirir → DRF hız sınırları (kayıt 5/saat, giriş 10/dk) IP başına çalışır. 2026-10-11 öncesi
    hepsi 127.0.0.1 sayıldı: tüm dünya TEK kovayı paylaşıyordu (biri 5 kayıt denemesiyle API kaydını herkese kapatabilirdi)."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        real = request.META.get("HTTP_X_REAL_IP", "").strip()
        if real and request.META.get("REMOTE_ADDR") in ("127.0.0.1", "::1"):
            request.META["REMOTE_ADDR"] = real
        return self.get_response(request)
