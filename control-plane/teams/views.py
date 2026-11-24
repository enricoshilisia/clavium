"""Team vault API (/api/teams/). The server enforces who may read, write
and manage; the cryptography makes sure it could not read anything even
if it wanted to."""

import base64
import time

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Account
from orgs.models import AuditLogEntry, Membership, Organization

from . import services
from .models import AccountKey, TeamAccess, TeamGroupRule, TeamItem, TeamVault

MAX_PUSH_ITEMS = 500
MAX_PULL_ITEMS = 1000
MAX_ITEM_BYTES = 1_000_000
LONG_POLL_SECONDS = 25
Role = TeamAccess.Role


def _b64_len(value, n=None, max_len=None):
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise serializers.ValidationError("not base64")
    if n is not None and len(raw) != n:
        raise serializers.ValidationError(f"must be {n} bytes")
    if max_len is not None and len(raw) > max_len:
        raise serializers.ValidationError("too long")
    return value


class WrappedKeySerializer(serializers.Serializer):
    ephemeral_public_key = serializers.CharField(max_length=64)
    nonce = serializers.CharField(max_length=32)
    ciphertext = serializers.CharField(max_length=128)

    def validate_ephemeral_public_key(self, v):
        return _b64_len(v, 32)

    def validate_nonce(self, v):
        return _b64_len(v, 12)

    def validate_ciphertext(self, v):
        return _b64_len(v, 48)  # 32-byte key + 16-byte tag


class AccountKeySerializer(serializers.Serializer):
    public_key = serializers.CharField(max_length=64)
    encrypted_private_key = serializers.CharField(max_length=256)

    def validate_public_key(self, v):
        return _b64_len(v, 32)

    def validate_encrypted_private_key(self, v):
        return _b64_len(v, max_len=128)


class ItemSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    revision = serializers.IntegerField(min_value=0)
    deleted = serializers.BooleanField()
    nonce = serializers.CharField(max_length=32)
    ciphertext = serializers.CharField(max_length=MAX_ITEM_BYTES * 2)


class GrantSerializer(serializers.Serializer):
    account_id = serializers.UUIDField()
    public_key = serializers.CharField(max_length=64)
    wrapped_key = WrappedKeySerializer()


def _access(team, account):
    return TeamAccess.objects.filter(team=team, account=account).select_related("team").first()


def _can_manage(team, account, access=None):
    access = access if access is not None else _access(team, account)
    return (access is not None and access.role == Role.MANAGER) or services.is_org_admin(team.organization, account)


def _team_for(request, team_id):
    """The team, if the caller is still an active org member."""
    team = get_object_or_404(TeamVault.objects.select_related("organization"), id=team_id)
    if not services.is_org_member(team.organization, request.user):
        return None
    return team


def _not_found():
    return Response({"detail": "no such team vault"}, status=404)


def _team_payload(team, access, can_manage):
    return {
        "id": str(team.id),
        "name": team.name,
        "organization": {"id": str(team.organization_id), "name": team.organization.name},
        "role": access.role if access else None,
        "can_manage": can_manage,
        "key_version": team.key_version,
        "needs_rotation": team.needs_rotation,
        "wrapped_key": access.wrapped_key if access and access.has_current_key else None,
        "pending": access is not None and not access.has_current_key,
    }


class AccountKeyView(APIView):
    def get(self, request):
        k = AccountKey.objects.filter(account=request.user).first()
        if k is None:
            return Response({"detail": "no account key yet"}, status=404)
        return Response({"public_key": k.public_key, "encrypted_private_key": k.encrypted_private_key})

    def put(self, request):
        s = AccountKeySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        with transaction.atomic():
            k = AccountKey.objects.select_for_update().filter(account=request.user).first()
            changed = k is None or k.public_key != s.validated_data["public_key"]
            if k is None:
                k = AccountKey(account=request.user)
            k.public_key = s.validated_data["public_key"]
            k.encrypted_private_key = s.validated_data["encrypted_private_key"]
            k.save()
            if changed:
                # Copies sealed to the old key can no longer be opened by
                # this person; a manager's app seals new ones.
                n = TeamAccess.objects.filter(account=request.user, wrapped_key__isnull=False).update(wrapped_key=None, sealed_to="")
                AuditLogEntry.record(organization=None, actor=request.user, action="team.account_key_set", obj=k, copies_reset=n)
        return Response({"public_key": k.public_key, "encrypted_private_key": k.encrypted_private_key})


class TeamListView(APIView):
    def get(self, request):
        accesses = {a.team_id: a for a in TeamAccess.objects.filter(account=request.user).select_related("team", "team__organization")}
        org_ids = Membership.objects.filter(account=request.user, removed_at__isnull=True).values_list("organization_id", flat=True)
        admin_orgs = set(
            Membership.objects.filter(account=request.user, removed_at__isnull=True, role__in=(Membership.Role.OWNER, Membership.Role.ADMIN)).values_list("organization_id", flat=True)
        )
        out = []
        for a in accesses.values():
            if a.team.organization_id in set(org_ids):
                out.append(_team_payload(a.team, a, a.role == Role.MANAGER or a.team.organization_id in admin_orgs))
        # Org admins also see teams they are not in, so they can manage them.
        for team in TeamVault.objects.filter(organization_id__in=admin_orgs).exclude(id__in=accesses.keys()).select_related("organization"):
            out.append(_team_payload(team, None, True))
        out.sort(key=lambda t: (t["organization"]["name"].lower(), t["name"].lower()))
        orgs = [
            {"id": str(m.organization_id), "name": m.organization.name, "can_create": m.organization_id in admin_orgs}
            for m in Membership.objects.filter(account=request.user, removed_at__isnull=True).select_related("organization")
        ]
        return Response({"teams": out, "organizations": orgs})

    def post(self, request):
        data = request.data
        try:
            team_id = serializers.UUIDField().to_internal_value(data.get("id"))
        except serializers.ValidationError:
            return Response({"detail": "id must be a UUID made by the app"}, status=400)
        name = str(data.get("name", "")).strip()[:200]
        if not name:
            return Response({"detail": "give the team vault a name"}, status=400)
        org = Organization.objects.filter(id=data.get("organization_id")).first() if data.get("organization_id") else None
        if org is None or not services.is_org_admin(org, request.user):
            return Response({"detail": "only owners and admins of the organization can create team vaults"}, status=403)
        if not AccountKey.objects.filter(account=request.user).exists():
            return Response({"detail": "set up your account key first"}, status=409)
        wk = WrappedKeySerializer(data=data.get("wrapped_key"))
        wk.is_valid(raise_exception=True)
        if TeamVault.objects.filter(id=team_id).exists():
            return Response({"detail": "that id is taken"}, status=409)
        with transaction.atomic():
            team = TeamVault.objects.create(id=team_id, organization=org, name=name, created_by=request.user)
            access = TeamAccess.objects.create(
                team=team, account=request.user, role=Role.MANAGER, wrapped_key=wk.validated_data, key_version=1,
                sealed_to=request.user.team_key.public_key, granted_by=request.user,
            )
            AuditLogEntry.record(organization=org, actor=request.user, action="team.created", obj=team, team=name)
        return Response(_team_payload(team, access, True), status=201)


class TeamDetailView(APIView):
    def patch(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can rename"}, status=403)
        name = str(request.data.get("name", "")).strip()[:200]
        if not name:
            return Response({"detail": "give the team vault a name"}, status=400)
        old, team.name = team.name, name
        team.save(update_fields=["name"])
        AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.renamed", obj=team, old=old, new=name)
        return Response(_team_payload(team, _access(team, request.user), True))

    def delete(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can delete a team vault"}, status=403)
        AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.deleted", obj=team, team=team.name, items=team.items.count())
        team.delete()
        return Response(status=204)


class MembersView(APIView):
    def get(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        me = _access(team, request.user)
        manage = _can_manage(team, request.user, me)
        if me is None and not manage:
            return _not_found()
        keys = dict(AccountKey.objects.filter(account__memberships__organization=team.organization).values_list("account_id", "public_key"))
        members = []
        for a in team.accesses.select_related("account").order_by("account__email"):
            members.append({
                "account_id": str(a.account_id), "email": a.account.email, "name": a.account.display_name,
                "role": a.role, "source": a.source, "has_key": a.has_current_key,
                "public_key": keys.get(a.account_id) if manage else None,
            })
        out = {"members": members, "can_manage": manage, "key_version": team.key_version, "needs_rotation": team.needs_rotation}
        if manage:
            in_team = {a.account_id for a in team.accesses.all()}
            out["candidates"] = [
                {"account_id": str(m.account_id), "email": m.account.email, "name": m.account.display_name, "public_key": keys.get(m.account_id)}
                for m in Membership.objects.filter(organization=team.organization, removed_at__isnull=True).select_related("account").order_by("account__email")
                if m.account_id not in in_team
            ]
            out["group_rules"] = [{"group_id": r.group_id, "group_name": r.group_name, "role": r.role} for r in team.group_rules.all()]
        return Response(out)

    def post(self, request, team_id):
        """Add a person. With `wrapped_key` they get access at once;
        without it they are pending until a manager's app seals a copy."""
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can add people"}, status=403)
        role = request.data.get("role", Role.EDITOR)
        if role not in Role.values:
            return Response({"detail": "unknown role"}, status=400)
        account = Account.objects.filter(id=request.data.get("account_id")).first()
        if account is None or not services.is_org_member(team.organization, account):
            return Response({"detail": "that person is not in this organization"}, status=400)
        with transaction.atomic():
            access, created = TeamAccess.objects.get_or_create(team=team, account=account, defaults={"role": role, "granted_by": request.user})
            if not created:
                access.role = role
                access.source = TeamAccess.Source.MANUAL
                access.save(update_fields=["role", "source"])
            if request.data.get("wrapped_key"):
                err = _apply_grant(team, access, request.data, request.user)
                if err:
                    transaction.set_rollback(True)
                    return err
            AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.member_added", obj=team, team=team.name, member_email=account.email, role=role)
        return Response({"account_id": str(account.id), "role": access.role, "has_key": access.has_current_key}, status=201 if created else 200)


def _apply_grant(team, access, data, actor):
    s = GrantSerializer(data={"account_id": str(access.account_id), **{k: data.get(k) for k in ("public_key", "wrapped_key")}})
    s.is_valid(raise_exception=True)
    key = AccountKey.objects.filter(account=access.account).first()
    if key is None or key.public_key != s.validated_data["public_key"]:
        return Response({"detail": f"{access.account.email} has a different key now; refresh and try again"}, status=409)
    if int(data.get("key_version", team.key_version)) != team.key_version:
        return Response({"detail": "the team key changed; refresh and try again", "key_version": team.key_version}, status=409)
    access.wrapped_key = s.validated_data["wrapped_key"]
    access.key_version = team.key_version
    access.sealed_to = key.public_key
    access.granted_by = actor
    access.save(update_fields=["wrapped_key", "key_version", "sealed_to", "granted_by"])
    return None


class MemberDetailView(APIView):
    def patch(self, request, team_id, account_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can change roles"}, status=403)
        access = get_object_or_404(TeamAccess, team=team, account_id=account_id)
        role = request.data.get("role")
        if role not in Role.values:
            return Response({"detail": "unknown role"}, status=400)
        if access.role == Role.MANAGER and role != Role.MANAGER and not team.accesses.filter(role=Role.MANAGER).exclude(id=access.id).exists():
            return Response({"detail": "a team vault needs at least one manager"}, status=409)
        old, access.role = access.role, role
        access.save(update_fields=["role"])
        AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.role_changed", obj=team, team=team.name, member_email=access.account.email, old=old, new=role)
        return Response({"account_id": str(access.account_id), "role": role})

    def delete(self, request, team_id, account_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        access = get_object_or_404(TeamAccess.objects.select_related("account", "team"), team=team, account_id=account_id)
        leaving_self = access.account_id == request.user.id
        if not leaving_self and not _can_manage(team, request.user):
            return Response({"detail": "only managers can remove people"}, status=403)
        if access.role == Role.MANAGER and not team.accesses.filter(role=Role.MANAGER).exclude(id=access.id).exists():
            return Response({"detail": "a team vault needs at least one manager; make someone else a manager first"}, status=409)
        services.remove_access(access, request.user, "left" if leaving_self else "removed by manager")
        return Response(status=204)


class GrantsView(APIView):
    """A manager's app seals copies of the current key for pending people."""

    def post(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        me = _access(team, request.user)
        if me is None or me.role != Role.MANAGER or not me.has_current_key:
            return Response({"detail": "only a manager holding the key can grant access"}, status=403)
        grants = request.data.get("grants") or []
        if not isinstance(grants, list) or len(grants) > 500:
            return Response({"detail": "grants must be a list"}, status=400)
        done, failed = [], []
        with transaction.atomic():
            for g in grants:
                access = TeamAccess.objects.filter(team=team, account_id=g.get("account_id")).select_related("account", "team").first()
                if access is None:
                    failed.append({"account_id": g.get("account_id"), "detail": "no longer has access"})
                    continue
                err = _apply_grant(team, access, {**g, "key_version": request.data.get("key_version")}, request.user)
                if err:
                    failed.append({"account_id": g.get("account_id"), "detail": err.data["detail"]})
                else:
                    done.append(str(access.account_id))
            if done:
                AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.access_granted", obj=team, team=team.name, accounts=len(done))
        return Response({"granted": done, "failed": failed})


class ItemsView(APIView):
    def get(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        access = _access(team, request.user)
        if access is None or not access.has_current_key:
            return Response({"detail": "you do not have the key for this team vault yet"}, status=403)
        try:
            since = int(request.query_params.get("since", "0"))
        except ValueError:
            return Response({"detail": "since must be an integer"}, status=400)
        if request.query_params.get("wait") == "1":
            deadline = time.monotonic() + LONG_POLL_SECONDS
            start_key = team.key_version
            # Wake on new items, or when the key is replaced (the app must
            # fetch its new copy and start again from 0).
            while team.counter <= since and team.key_version == start_key and time.monotonic() < deadline:
                time.sleep(1)
                team.refresh_from_db(fields=["counter", "key_version", "needs_rotation"])
        rows = list(TeamItem.objects.filter(team=team, revision__gt=since).order_by("revision")[: MAX_PULL_ITEMS + 1])
        has_more = len(rows) > MAX_PULL_ITEMS
        rows = rows[:MAX_PULL_ITEMS]
        cursor = rows[-1].revision if has_more else max(team.counter, since)
        return Response({"items": [r.as_wire() for r in rows], "cursor": cursor, "has_more": has_more, "key_version": team.key_version, "needs_rotation": team.needs_rotation})

    def post(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        items = ItemSerializer(data=request.data.get("items") or [], many=True)
        items.is_valid(raise_exception=True)
        if len(items.validated_data) > MAX_PUSH_ITEMS:
            return Response({"detail": f"at most {MAX_PUSH_ITEMS} items per push"}, status=400)
        results = []
        with transaction.atomic():
            team = TeamVault.objects.select_for_update().get(id=team.id)
            access = _access(team, request.user)
            if access is None or not access.has_current_key:
                return Response({"detail": "you do not have the key for this team vault"}, status=403)
            if not access.can_write:
                return Response({"detail": "you can view this team vault but not change it"}, status=403)
            if request.data.get("key_version") != team.key_version:
                return Response({"detail": "the team key was replaced; pull again", "key_version": team.key_version}, status=409)
            existing = {r.item_id: r for r in TeamItem.objects.filter(team=team, item_id__in=[i["id"] for i in items.validated_data])}
            for item in items.validated_data:
                size = len(item["ciphertext"])
                if size > MAX_ITEM_BYTES * 4 // 3 + 4:
                    results.append({"id": str(item["id"]), "status": "rejected", "detail": "item too large"})
                    continue
                row = existing.get(item["id"])
                current = row.revision if row else 0
                if item["revision"] != current:
                    results.append({"id": str(item["id"]), "status": "conflict", "revision": current})
                    continue
                team.counter += 1
                row = row or TeamItem(team=team, item_id=item["id"])
                row.revision, row.deleted, row.nonce, row.ciphertext = team.counter, item["deleted"], item["nonce"], item["ciphertext"]
                row.size_bytes, row.updated_by = size, request.user
                row.save()
                results.append({"id": str(item["id"]), "status": "ok", "revision": row.revision})
            team.save(update_fields=["counter"])
        return Response({"results": results, "cursor": team.counter})


class RotateView(APIView):
    """Replace the team key: all content re-encrypted under the new key and
    new sealed copies for everyone who keeps access, in one step."""

    def post(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        items = ItemSerializer(data=request.data.get("items") or [], many=True)
        items.is_valid(raise_exception=True)
        grants = request.data.get("grants") or []
        if not isinstance(grants, list):
            return Response({"detail": "grants must be a list"}, status=400)
        with transaction.atomic():
            team = TeamVault.objects.select_for_update().get(id=team.id)
            me = _access(team, request.user)
            if me is None or me.role != Role.MANAGER or not me.has_current_key:
                return Response({"detail": "only a manager holding the key can replace it"}, status=403)
            if request.data.get("key_version") != team.key_version + 1:
                return Response({"detail": "key_version must be the current version + 1", "key_version": team.key_version}, status=409)
            if str(request.user.id) not in {str(g.get("account_id")) for g in grants}:
                return Response({"detail": "include a copy for yourself"}, status=400)
            team.key_version += 1
            accesses = {str(a.account_id): a for a in TeamAccess.objects.filter(team=team).select_related("account", "team")}
            for a in accesses.values():
                a.wrapped_key, a.sealed_to = None, ""
                a.save(update_fields=["wrapped_key", "sealed_to"])
            for g in grants:
                a = accesses.get(str(g.get("account_id")))
                if a is None:
                    continue  # removed meanwhile: simply gets no copy
                a.team = team
                err = _apply_grant(team, a, {**g, "key_version": team.key_version}, request.user)
                if err:
                    transaction.set_rollback(True)
                    return err
            TeamItem.objects.filter(team=team).delete()
            for item in items.validated_data:
                team.counter += 1
                TeamItem.objects.create(
                    team=team, item_id=item["id"], revision=team.counter, deleted=False, nonce=item["nonce"],
                    ciphertext=item["ciphertext"], size_bytes=len(item["ciphertext"]), updated_by=request.user,
                )
            team.needs_rotation = False
            team.save(update_fields=["key_version", "counter", "needs_rotation"])
            AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.key_rotated", obj=team, team=team.name, key_version=team.key_version, copies=len(grants), items=len(items.validated_data))
        return Response({"key_version": team.key_version, "cursor": team.counter})


class GroupRulesView(APIView):
    def get(self, request, team_id):
        """Search the organization's Microsoft 365 groups (managers)."""
        from entra import graph
        from entra.models import DirectoryConnection

        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can change group access"}, status=403)
        conn = DirectoryConnection.objects.filter(organization=team.organization).first()
        if conn is None:
            return Response({"connected": False, "groups": []})
        try:
            groups = graph.client_for(conn.tenant_id).search_groups(str(request.query_params.get("q", ""))[:100], limit=15)
        except graph.GraphError as e:
            return Response({"detail": str(e)}, status=502)
        return Response({"connected": True, "groups": [{"id": g["id"], "name": g["name"]} for g in groups]})

    def post(self, request, team_id):
        from entra import graph
        from entra.models import DirectoryConnection

        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can change group access"}, status=403)
        conn = DirectoryConnection.objects.filter(organization=team.organization).first()
        if conn is None:
            return Response({"detail": "connect Microsoft 365 for this organization first"}, status=409)
        role = request.data.get("role", Role.EDITOR)
        if role not in Role.values:
            return Response({"detail": "unknown role"}, status=400)
        try:
            g = graph.client_for(conn.tenant_id).group(str(request.data.get("group_id", "")))
        except graph.GraphError as e:
            return Response({"detail": str(e)}, status=400)
        TeamGroupRule.objects.update_or_create(team=team, group_id=g["id"], defaults={"group_name": g["name"], "role": role})
        AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.group_rule_set", obj=team, team=team.name, group=g["name"], role=role)
        return Response({"group_id": g["id"], "group_name": g["name"], "role": role, "note": "Applied at the next Microsoft 365 sync."}, status=201)

    def delete(self, request, team_id):
        team = _team_for(request, team_id)
        if team is None:
            return _not_found()
        if not _can_manage(team, request.user):
            return Response({"detail": "only managers can change group access"}, status=403)
        n, _ = TeamGroupRule.objects.filter(team=team, group_id=request.query_params.get("group_id", "")).delete()
        if n:
            services.apply_group_rules(team.organization, request.user)
            AuditLogEntry.record(organization=team.organization, actor=request.user, action="team.group_rule_removed", obj=team, team=team.name)
        return Response(status=204)
