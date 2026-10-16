from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Account, Device, DeviceToken
from .serializers import DeviceRegisterSerializer, DeviceSerializer, RegisterSerializer


class RegisterView(APIView):
    """Create an account. Does not log in or register a device — those are
    separate steps, so creating an account never implicitly trusts
    whatever machine happened to make the HTTP request.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        account = Account.objects.create_user(
            email=data["email"],
            password=data["password"],
            display_name=data.get("display_name", ""),
        )
        return Response(
            {"id": str(account.id), "email": account.email},
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

    def post(self, request):
        serializer = DeviceRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        account = authenticate(
            request, username=data["email"], password=data["password"]
        )
        if account is None:
            return Response({"detail": "invalid email or password"}, status=401)

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
                "account": {"id": str(account.id), "email": account.email},
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
