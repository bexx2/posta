from django.contrib.auth import login, logout
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from . import services


class AuthThrottle(AnonRateThrottle):
    scope = "auth"          # IP başına; ayarlar: DEFAULT_THROTTLE_RATES["auth"]
    rate = "10/min"


class RegisterThrottle(AnonRateThrottle):
    scope = "register"
    rate = "5/hour"


def err(code, message, http=400):
    return Response({"error": {"code": code, "message": message}}, status=http)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [RegisterThrottle]

    class In(serializers.Serializer):
        email = serializers.CharField(max_length=254)
        password = serializers.CharField(max_length=128, trim_whitespace=False)
        accepted_version = serializers.CharField(max_length=32)

    def post(self, request):
        s = self.In(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            user = services.register(**s.validated_data)
        except services.RegistrationError as e:
            return err(e.code, e.message)
        if user:
            services.send_verification(user)
        # Hesap var olsa da yoksa da aynı yanıt
        return Response({"status": "check_your_email"}, status=status.HTTP_202_ACCEPTED)


class VerifyView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [AuthThrottle]

    def post(self, request):
        user = services.confirm_email(str(request.data.get("token", "")))
        if not user:
            return err("invalid_token", "This link is invalid or has expired.")
        return Response({"status": "verified"})


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]

    def post(self, request):
        try:
            user = services.login_user(request, request.data.get("email"), request.data.get("password"))
        except services.RegistrationError as e:
            return err(e.code, e.message, 401 if e.code == "invalid_credentials" else 403)
        login(request, user)
        return Response({"status": "ok", "email": user.email})


class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"status": "ok"})


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        u = request.user
        return Response({"email": u.email, "email_verified": u.is_email_verified})
