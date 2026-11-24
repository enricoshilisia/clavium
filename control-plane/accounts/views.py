from django.contrib.auth import authenticate
from django.shortcuts import render
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from . import email_verification
from .models import Account, Device, DeviceToken
from .serializers import DeviceRegisterSerializer, DeviceSerializer, RegisterSerializer


class RegisterView(APIView):
    """Create an account. Does not log in or register a device — those are
    separate steps, so creating an account never implicitly trusts
    whatever machine happened to make the HTTP request.
    """

    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        account = Account.objects.create_user(
            email=data["email"],
            password=data["password"],
            display_name=data.get("display_name", ""),
        )
        if email_verification.enabled():
            email_verification.send(account, request)
        return Response(
            {"id": str(account.id), "email": account.email, **email_verification.status(account)},
            status=201,
        )


class DeviceRegisterView(APIView):
    """Exchange account credentials for a device bearer token.

    `client_device_id` is generated once by the client and persisted
    locally; registering the same id again rotates that device's token
    rather than creating a duplicate. A device that has been revoked
    cannot resurrect itself this way — a fresh install must mint a new
    `client_device_id`, so a stolen, revoked laptop cannot just
    re-authenticate its way back in with the account password alone.
    """

    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        serializer = DeviceRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        account = authenticate(
            request, username=data["email"], password=data["password"]
        )
        if account is None:
            return Response({"detail": "invalid email or password"}, status=401)

        # Only checked after the password matched, so it reveals nothing
        # about which addresses have accounts.
        if email_verification.blocks_sign_in(account):
            email_verification.send(account, request)
            return Response(
                {
                    "code": "email_not_verified",
                    "detail": f"Verify your email address before signing in. We sent a code to {account.email}.",
                },
                status=403,
            )

        device = Device.objects.filter(
            account=account, client_device_id=data["client_device_id"]
        ).first()

        if device is not None and device.is_revoked:
            return Response(
                {"detail": "this device was revoked; reinstall to register as a new device"},
                status=403,
            )

        public_key = data.get("public_key", "")

        if device is None:
            device = Device.objects.create(
                account=account,
                client_device_id=data["client_device_id"],
                name=data["name"],
                platform=data.get("platform", ""),
                public_key=public_key,
            )
        else:
            if public_key and device.public_key and public_key != device.public_key:
                # Silently swapping the key here would orphan every shared
                # vault this device already holds a wrapped grant for —
                # those grants are bound to the specific keypair, not the
                # device row. A real rotation is a revoke-and-re-register,
                # not something that happens as a side effect of login.
                return Response(
                    {
                        "detail": "this device already has a different public key on file; "
                        "revoke it and register as a new device to rotate keys"
                    },
                    status=409,
                )
            device.name = data["name"]
            device.platform = data.get("platform", "")
            if public_key and not device.public_key:
                device.public_key = public_key
            device.save(update_fields=["name", "platform", "public_key"])
            device.tokens.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())

        _, raw_token = DeviceToken.issue(device)

        return Response(
            {
                "device_id": str(device.id),
                "token": raw_token,
                "account": {"id": str(account.id), "email": account.email, **email_verification.status(account)},
            },
            status=201,
        )


class DeviceListView(APIView):
    def get(self, request):
        devices = request.user.devices.order_by("-created_at")
        serializer = DeviceSerializer(
            devices, many=True, context={"current_device": request.auth}
        )
        return Response(serializer.data)


class DeviceRevokeView(APIView):
    """Revoke one of the account's own devices. A device may revoke
    itself — there is no special-case guard against that — which is the
    legitimate way to end a session from the device that is on it.
    """

    def post(self, request, device_id):
        device = request.user.devices.filter(id=device_id).first()
        if device is None:
            return Response({"detail": "no such device"}, status=404)

        now = timezone.now()
        device.revoked_at = now
        device.save(update_fields=["revoked_at"])
        device.tokens.filter(revoked_at__isnull=True).update(revoked_at=now)

        return Response(status=204)


def _account_for(request, email: str):
    if request.user.is_authenticated:
        return request.user
    if not email:
        return None
    return Account.objects.filter(email__iexact=Account.objects.normalize_email(email)).first()


class MeView(APIView):
    """The signed-in account, including whether its email is verified."""

    def get(self, request):
        account = request.user
        return Response(
            {"id": str(account.id), "email": account.email, "display_name": account.display_name, **email_verification.status(account)}
        )


class EmailVerificationSendView(APIView):
    """Send (or resend) the verification email.

    Works signed in, or with just an email so someone blocked at sign-in
    can ask for a new code. The answer never says whether an account
    exists, so this cannot be used to discover who has one.
    """

    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        if not email_verification.enabled():
            return Response({"detail": "Email verification is not turned on."}, status=404)
        account = _account_for(request, str(request.data.get("email", "")).strip())
        result = email_verification.send(account, request) if account is not None else email_verification.SendResult.SENT
        if request.user.is_authenticated:
            if result == email_verification.SendResult.ALREADY_VERIFIED:
                return Response({"detail": "This email address is already verified.", "email_verified": True})
            if result == email_verification.SendResult.TOO_SOON:
                return Response({"detail": "A code was sent less than a minute ago. Check your inbox and spam folder."}, status=429)
            if result == email_verification.SendResult.LIMIT:
                return Response({"detail": "Too many codes this hour. Try again later."}, status=429)
        return Response({"detail": "If this account needs verifying, a code is on its way. It works for 30 minutes."}, status=202)


class EmailVerificationConfirmView(APIView):
    """Confirm with the 6-digit code from the email."""

    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        if not email_verification.enabled():
            return Response({"detail": "Email verification is not turned on."}, status=404)
        code = str(request.data.get("code", "")).strip()
        account = _account_for(request, str(request.data.get("email", "")).strip())
        if account is not None and account.email_verified:
            return Response({"email_verified": True})
        if account is None or not code.isdigit() or len(code) != 6 or not email_verification.verify_code(account, code):
            return Response({"detail": "That code is wrong or has expired. Ask for a new one."}, status=400)
        return Response({"email_verified": True})


def verify_email_page(request):
    """The link in the email. GET only shows a button, so mail scanners
    that open links on their own do not verify anything; the POST does."""
    token = request.GET.get("t", "") or request.POST.get("t", "")
    if not email_verification.enabled():
        return render(request, "accounts/verify_email.html", {"state": "off"}, status=404)
    if request.method == "POST":
        account = email_verification.verify_link(token)
        return render(request, "accounts/verify_email.html", {"state": "done" if account else "invalid", "email": account.email if account else ""}, status=200 if account else 400)
    challenge = email_verification.find_by_link(token)
    if challenge is None:
        return render(request, "accounts/verify_email.html", {"state": "invalid"}, status=400)
    return render(request, "accounts/verify_email.html", {"state": "confirm", "token": token, "email": challenge.email})
