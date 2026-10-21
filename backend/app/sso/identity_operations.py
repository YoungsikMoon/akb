"""Bounded machine authority issued by a human administrator.

The permanent provider PAT is never migration authority. A grant delegates one
exact cohort, provider revision and runtime boundary; the operation credential
is usable only here and is stored only as a hash. All AKB writes and their
idempotency receipts commit together. Keycloak is only read by this module.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hashlib
import json
import secrets
from typing import Any
import uuid

from app.db.postgres import get_pool
from app.exceptions import AKBError
from app.repositories.events_repo import emit_event
from app.services.sso_session_epoch import (
    current_sso_session_authority,
    lock_active_sso_session_epoch,
)
from app.sso import identity_migration
from app.sso.keycloak_admin import ProviderControlError, get_keycloak_provider_control
from app.sso.providers.keycloak_oidc import ProviderDefinitionError, validate_alias


CAPABILITIES = [
    "sso.provider-ownership.v1",
    "sso.identity-operation.v1",
    "sso.enabled-exact-admission.v1",
]
IDENTITY_VERBS = frozenset({"preflight", "apply", "rollback", "admit"})
PROVIDER_VERBS = frozenset({"configure", "enable", "disable"})
VERBS = IDENTITY_VERBS | PROVIDER_VERBS
PREFIX = "akb_sso_operation_"


def _error(code: str, status: int = 409) -> AKBError:
    return AKBError("SSO operation authority rejected", status_code=status, code=code)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _object(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(_json(value).encode()).hexdigest()
    except (UnicodeEncodeError, ValueError, TypeError):
        raise _error("sso_operation_request_invalid", 422) from None


def provider_fingerprint(provider, *, alias: str | None = None) -> str:
    # Keycloak masks secrets. This fingerprint detects public configuration
    # drift, not an out-of-band replacement of a masked secret.
    return _digest(provider.admin_view() if provider is not None else {"provider_alias": alias, "state": "absent"})


def _canonical_alias(alias: str) -> str:
    try:
        canonical = validate_alias(alias)
    except ProviderDefinitionError:
        raise _error("provider_alias_invalid", 422) from None
    # Keycloak's provider adapter normalizes NFC and strips whitespace. Never
    # authorize or lock a different spelling from the alias it will mutate.
    if canonical != alias:
        raise _error("provider_alias_invalid", 422)
    return canonical


async def _provider(alias: str, *, allow_missing: bool = False, allow_configuration_error: bool = False):
    alias = _canonical_alias(alias)
    providers = await get_keycloak_provider_control().list_providers(force_refresh=True)
    selected = [provider for provider in providers if provider.alias == alias]
    if not selected and allow_missing:
        return None
    if len(selected) != 1 or (selected[0].state == "configuration_error" and not allow_configuration_error):
        raise _error("sso_operation_provider_unavailable")
    return selected[0]


async def _alias_lock(conn, alias: str):
    alias = _canonical_alias(alias)
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", f"sso-provider-owner:{alias}")


async def capabilities() -> dict[str, Any]:
    pool = await get_pool()
    installation = await pool.fetchval("SELECT installation_id FROM sso_operation_installation WHERE singleton")
    realm_identity = None
    realm_error = None
    try:
        realm_identity = await get_keycloak_provider_control().read_realm_identity()
    except ProviderControlError as error:
        realm_error = error.code
    return {"schema_version": 1, "installation_id": str(installation),
            "capabilities": CAPABILITIES, "max_ttl_seconds": 600, "max_nonce_age_seconds": 300,
            "realm_identity": realm_identity, "realm_identity_error": realm_error}


async def ownership(alias: str) -> dict[str, Any]:
    provider = await _provider(alias, allow_missing=True, allow_configuration_error=True)
    pool = await get_pool()
    row = await pool.fetchrow("SELECT * FROM sso_provider_ownership WHERE alias=$1", alias)
    return {"schema_version": 1, "provider_alias": alias,
            "owner_id": row["owner_id"] if row else None,
            "revision": row["revision"] if row else 0,
            "fingerprint": provider_fingerprint(provider, alias=alias),
            "drifted": bool(row and row["fingerprint"] != provider_fingerprint(provider, alias=alias)),
            "emergency_disabled": bool(row and row["emergency_disabled"])}


async def set_ownership(alias: str, *, owner_id: str | None, expected_revision: int,
                        expected_fingerprint: str, clear_emergency: bool, actor_id: uuid.UUID) -> dict[str, Any]:
    alias = _canonical_alias(alias)
    if owner_id is not None and (not owner_id or len(owner_id) > 255
        or any(ord(character) < 0x20 or ord(character) == 0x7f for character in owner_id)):
        raise _error("sso_provider_owner_invalid", 422)
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        await _alias_lock(conn, alias)
        row = await conn.fetchrow("SELECT * FROM sso_provider_ownership WHERE alias=$1 FOR UPDATE", alias)
        if (row["revision"] if row else 0) != expected_revision:
            raise _error("sso_provider_revision_conflict")
        provider = await _provider(alias, allow_missing=True, allow_configuration_error=owner_id is None)
        fingerprint = provider_fingerprint(provider, alias=alias)
        if fingerprint != expected_fingerprint:
            raise _error("sso_provider_fingerprint_conflict")
        emergency = bool(row and row["emergency_disabled"] and not clear_emergency)
        await conn.execute("""INSERT INTO sso_provider_ownership
            (alias,owner_id,revision,fingerprint,emergency_disabled,updated_by)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(alias) DO UPDATE SET
            owner_id=EXCLUDED.owner_id,revision=EXCLUDED.revision,fingerprint=EXCLUDED.fingerprint,
            emergency_disabled=EXCLUDED.emergency_disabled,updated_by=EXCLUDED.updated_by,updated_at=NOW()""",
            alias, owner_id, expected_revision + 1, fingerprint, emergency, actor_id)
        await emit_event(conn, "auth.sso_provider_ownership_changed", actor_id=str(actor_id),
                         payload={"provider_alias": alias, "owner_id": owner_id, "revision": expected_revision + 1,
                                  "emergency_disabled": emergency})
    return await ownership(alias)


@asynccontextmanager
async def provider_mutation_guard(alias: str, actor, *, enabled: bool | None = None):
    """Serialize ordinary writes against grants; retain human emergency disable.

    Unowned providers retain standalone management. Releasing/adopting ownership
    is a separate, explicit human-admin CAS operation.
    """
    alias = _canonical_alias(alias)
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        await _alias_lock(conn, alias)
        row = await conn.fetchrow("SELECT * FROM sso_provider_ownership WHERE alias=$1 FOR UPDATE", alias)
        human = getattr(actor, "account_kind", "human") == "human" and actor.auth_method == "keycloak"
        emergency = bool(row and row["owner_id"] is not None and human and enabled is False)
        if row and row["owner_id"] is not None and not emergency:
            raise _error("sso_provider_owned_mutation_forbidden", 403)

        async def complete(provider):
            if row:
                await conn.execute("""UPDATE sso_provider_ownership SET revision=revision+1,fingerprint=$2,
                    emergency_disabled=emergency_disabled OR $3,updated_by=$4,updated_at=NOW() WHERE alias=$1""",
                    alias, provider_fingerprint(provider), emergency, uuid.UUID(str(actor.user_id)))
        yield complete


async def _live_actor(conn, row):
    # Locks serialize token revocation and human demotion with the mutation.
    machine = await conn.fetchrow("""SELECT t.id,t.expires_at FROM tokens t JOIN users u ON u.id=t.user_id
        WHERE t.id=$1 AND t.user_id=$2 AND t.key_class='service'
        AND t.scopes @> ARRAY['read','write','admin']::text[]
        AND (t.expires_at IS NULL OR t.expires_at>clock_timestamp())
        AND u.account_status='active' AND u.account_kind='service' AND u.is_admin
        FOR SHARE OF t,u""", row["actor_token_id"], row["actor_id"])
    human = await conn.fetchrow("""SELECT id FROM users WHERE id=$1 AND is_admin
        AND account_status='active' AND account_kind='human' AND auth_provider='keycloak' FOR SHARE""",
        row["granted_by"])
    now = await conn.fetchval("SELECT clock_timestamp()")
    if machine is None or human is None or (machine["expires_at"] is not None and machine["expires_at"] <= now):
        raise _error("sso_operation_actor_retired", 403)
    return machine["expires_at"]


async def _check_window(conn, row, request, *, actor_expires_at=None):
    # NOW() is the transaction start time and can remain valid after a lock
    # wait crosses expiry. Recheck the real clock after waits and before effects.
    now = await conn.fetchval("SELECT clock_timestamp()")
    if row["retired_at"] is not None or row["expires_at"] <= now:
        raise _error("sso_operation_retired", 403)
    if actor_expires_at is not None and actor_expires_at <= now:
        raise _error("sso_operation_actor_retired", 403)
    if request["issued_at"].tzinfo is None or not timedelta(seconds=0) <= now-request["issued_at"] <= timedelta(seconds=300):
        raise _error("sso_operation_nonce_expired", 403)


async def grant(spec: dict[str, Any], *, granted_by: uuid.UUID) -> dict[str, Any]:
    verbs = set(spec["verbs"])
    payload_hashes = spec.get("provider_payload_sha256", {})
    if (not verbs or not verbs <= VERBS or len(spec["verbs"]) != len(verbs)
        or not 1 <= spec["ttl_seconds"] <= 600 or len(spec["cohort"]) > 25
        or (bool(verbs & IDENTITY_VERBS) != bool(spec["cohort"]))
        or set(payload_hashes) != verbs & PROVIDER_VERBS
        or any(not isinstance(value, str) or len(value) != 64
               or any(character not in "0123456789abcdef" for character in value) for value in payload_hashes.values())):
        raise _error("sso_operation_scope_invalid", 422)
    authority = current_sso_session_authority()
    if spec["runtime_generation"] != authority.runtime_generation or spec["sso_session_epoch"] != authority.session_epoch:
        raise _error("sso_operation_runtime_conflict")
    cohort = []
    for item in spec["cohort"]:
        # Shared value-less validation preserves opaque identity bytes.
        uid = identity_migration._user_uuid(item["existing_user_id"])
        upstream = identity_migration._identity_part(item["upstream_subject"], kind="subject")
        broker = identity_migration._identity_part(item["broker_subject"], kind="subject")
        cohort.append({"existing_user_id": str(uid), "upstream_subject": upstream, "broker_subject": broker})
    if len({_json(item) for item in cohort}) != len(cohort):
        raise _error("sso_operation_cohort_duplicate", 422)
    raw = PREFIX + secrets.token_urlsafe(32)
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        await _alias_lock(conn, spec["provider_alias"])
        await lock_active_sso_session_epoch(conn, authority)
        owner = await conn.fetchrow("SELECT * FROM sso_provider_ownership WHERE alias=$1 FOR UPDATE", spec["provider_alias"])
        if not owner or owner["owner_id"] != spec["owner_id"] or owner["revision"] != spec["expected_provider_revision"]:
            raise _error("sso_provider_revision_conflict")
        if owner["emergency_disabled"]:
            raise _error("sso_provider_emergency_disabled")
        provider = await _provider(spec["provider_alias"], allow_missing=not bool(verbs & IDENTITY_VERBS))
        fingerprint = provider_fingerprint(provider, alias=spec["provider_alias"])
        if fingerprint != owner["fingerprint"]:
            raise _error("sso_provider_fingerprint_conflict")
        if verbs & IDENTITY_VERBS and (provider is None or not provider.supports_identity_migration):
            raise _error("sso_operation_migration_unsupported")
        installation = await conn.fetchval("SELECT installation_id FROM sso_operation_installation WHERE singleton")
        if spec["installation_id"] != installation:
            raise _error("sso_operation_installation_conflict")
        row = {"actor_id": spec["actor_id"], "actor_token_id": spec["actor_token_id"], "granted_by": granted_by}
        await _live_actor(conn, row)
        # Grant only cohorts that already possess the exact upstream binding.
        # No email lookup, no local-account conversion, no new user creation.
        for item in cohort:
            prelink = await _verify_item(spec["provider_alias"], item)
            item["upstream_issuer"] = prelink.upstream_issuer
            item["broker_issuer"] = prelink.broker_issuer
            await identity_migration._inspect_in_conn(conn,
                user_id=uuid.UUID(item["existing_user_id"]), old_issuer=prelink.upstream_issuer,
                old_subject=item["upstream_subject"], new_issuer=prelink.broker_issuer,
                new_subject=item["broker_subject"], lock_user=True)
        if await conn.fetchval("SELECT EXISTS(SELECT 1 FROM sso_identity_operations WHERE operation_id=$1)", spec["operation_id"]):
            raise _error("sso_operation_id_conflict")
        cohort_hash = _digest(cohort)
        expires = await conn.fetchval("SELECT NOW()+$1*INTERVAL '1 second'", spec["ttl_seconds"])
        await conn.execute("""INSERT INTO sso_identity_operations
            (operation_id,installation_id,credential_hash,granted_by,actor_id,actor_token_id,
             provider_alias,owner_id,provider_revision,provider_fingerprint,runtime_generation,session_epoch,
             cohort,cohort_sha256,verbs,expires_at,current_provider_revision,current_provider_fingerprint,provider_payload_sha256)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$9,$10,$17::jsonb)""",
            spec["operation_id"], installation, hashlib.sha256(raw.encode()).hexdigest(), granted_by,
            spec["actor_id"], spec["actor_token_id"], spec["provider_alias"], spec["owner_id"], owner["revision"],
            fingerprint, authority.runtime_generation, authority.session_epoch, _json(cohort), cohort_hash,
            spec["verbs"], expires, _json(payload_hashes))
        await emit_event(conn, "auth.sso_identity_operation_granted", actor_id=str(granted_by),
                         payload={"operation_id": str(spec["operation_id"]), "provider_alias": spec["provider_alias"],
                                  "cohort_sha256": cohort_hash, "cohort_count": len(cohort), "verbs": spec["verbs"]})
    return {"schema_version": 1, "operation_id": str(spec["operation_id"]), "credential": raw,
            "expires_at": expires.isoformat(), "cohort_sha256": cohort_hash, "provider_revision": owner["revision"]}


async def _verify_item(alias: str, item):
    return await get_keycloak_provider_control().verify_identity_prelink(alias,
        broker_subject=item["broker_subject"], upstream_subject=item["upstream_subject"])


async def _execute_provider(conn, row, request, request_hash, actor_expires_at):
    """One preapproved provider write through the existing security profile.

    The journal stores a digest and redacted readback, never the payload. A
    Keycloak success followed by process/DB failure is detected as fingerprint
    drift on retry. It needs explicit human reconciliation rather than a blind
    replay that could overwrite a security disable.
    """
    from app.api.routes.admin_sso import ConfigureProviderRequest
    from app.sso.models import ProviderConfigureSpec
    from pydantic import ValidationError

    verb, payload = request["verb"], request.get("payload")
    hashes = _object(row["provider_payload_sha256"])
    if request["item_index"] != 0 or not isinstance(payload, dict) or hashes.get(verb) != _digest(payload):
        raise _error("sso_operation_payload_conflict", 403)
    control = get_keycloak_provider_control()
    if verb == "configure":
        try:
            spec = ConfigureProviderRequest.model_validate(payload)
        except ValidationError:
            raise _error("sso_operation_request_invalid", 422) from None
        if spec.client_secret is not None and not isinstance(spec.client_secret, str):
            raise _error("sso_operation_request_invalid", 422)
        await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
        mutation = await control.configure(ProviderConfigureSpec(alias=row["provider_alias"], **spec.model_dump()))
    else:
        if payload:
            raise _error("sso_operation_payload_conflict", 403)
        await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
        mutation = await control.set_enabled(row["provider_alias"], enabled=verb == "enable")
    await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
    revision = row["current_provider_revision"] + 1
    fingerprint = provider_fingerprint(mutation.after)
    await conn.execute("""UPDATE sso_provider_ownership SET revision=$2,fingerprint=$3,
        updated_by=$4,updated_at=NOW() WHERE alias=$1""", row["provider_alias"], revision, fingerprint, row["actor_id"])
    await conn.execute("""UPDATE sso_identity_operations SET current_provider_revision=$2,
        current_provider_fingerprint=$3 WHERE operation_id=$1""", row["operation_id"], revision, fingerprint)
    result = {"schema_version": 1, "operation_id": str(row["operation_id"]), "nonce": str(request["nonce"]),
              "verb": verb, "provider_revision": revision, "provider": mutation.after.admin_view()}
    await conn.execute("""INSERT INTO sso_identity_operation_requests(operation_id,nonce,request_sha256,result)
        VALUES($1,$2,$3,$4::jsonb)""", row["operation_id"], request["nonce"], request_hash, _json(result))
    await emit_event(conn, "auth.sso_provider_operation_executed", actor_id=str(row["actor_id"]),
                     payload={"operation_id": str(row["operation_id"]), "verb": verb,
                              "provider_alias": row["provider_alias"], "provider_revision": revision,
                              "request_sha256": request_hash})
    return result


async def execute(operation_id: uuid.UUID, credential: str, request: dict[str, Any]) -> dict[str, Any]:
    if not credential.startswith(PREFIX) or len(credential) > 256:
        raise _error("sso_operation_credential_invalid", 401)
    request_hash = _digest({**request, "nonce": str(request["nonce"]), "issued_at": request["issued_at"].isoformat()})
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow("SELECT * FROM sso_identity_operations WHERE operation_id=$1 FOR UPDATE", operation_id)
        if row is None or not secrets.compare_digest(row["credential_hash"], hashlib.sha256(credential.encode()).hexdigest()):
            raise _error("sso_operation_credential_invalid", 401)
        await _check_window(conn, row, request)
        authority = current_sso_session_authority()
        await lock_active_sso_session_epoch(conn, authority)
        if (row["runtime_generation"], row["session_epoch"]) != (authority.runtime_generation, authority.session_epoch):
            raise _error("sso_operation_runtime_conflict")
        installation = await conn.fetchval("SELECT installation_id FROM sso_operation_installation WHERE singleton")
        if row["installation_id"] != installation:
            raise _error("sso_operation_installation_conflict")
        actor_expires_at = await _live_actor(conn, row)
        await _alias_lock(conn, row["provider_alias"])
        owner = await conn.fetchrow("SELECT * FROM sso_provider_ownership WHERE alias=$1 FOR UPDATE", row["provider_alias"])
        if not owner or (owner["owner_id"], owner["revision"], owner["fingerprint"]) != (row["owner_id"], row["current_provider_revision"], row["current_provider_fingerprint"]):
            raise _error("sso_provider_revision_conflict")
        if owner["emergency_disabled"]:
            raise _error("sso_provider_emergency_disabled")
        provider = await _provider(row["provider_alias"], allow_missing=not bool(set(row["verbs"]) & IDENTITY_VERBS))
        if provider_fingerprint(provider, alias=row["provider_alias"]) != row["current_provider_fingerprint"]:
            raise _error("sso_provider_fingerprint_conflict")
        await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
        previous = await conn.fetchrow("SELECT * FROM sso_identity_operation_requests WHERE operation_id=$1 AND nonce=$2", operation_id, request["nonce"])
        if previous:
            if previous["request_sha256"] != request_hash:
                raise _error("sso_operation_nonce_conflict")
            return _object(previous["result"])
        verb, index = request["verb"], request["item_index"]
        cohort = _object(row["cohort"])
        if verb not in VERBS or verb not in row["verbs"]:
            raise _error("sso_operation_scope_forbidden", 403)
        if verb in PROVIDER_VERBS:
            return await _execute_provider(conn, row, request, request_hash, actor_expires_at)
        if request.get("payload") is not None or not 0 <= index < len(cohort):
            raise _error("sso_operation_scope_forbidden", 403)
        item = cohort[index]
        prelink = await _verify_item(row["provider_alias"], item)
        if (prelink.upstream_issuer, prelink.broker_issuer) != (item["upstream_issuer"], item["broker_issuer"]):
            raise _error("sso_operation_issuer_conflict")
        if verb in {"apply", "rollback"} and prelink.provider_state != "configured_disabled":
            raise _error("identity_migration_provider_must_be_disabled")
        if verb == "admit" and prelink.provider_state != "enabled":
            raise _error("sso_operation_admission_provider_must_be_enabled")
        uid = uuid.UUID(item["existing_user_id"])
        for key in sorted({identity_migration._lock_key(prelink.upstream_issuer, item["upstream_subject"]),
                           identity_migration._lock_key(prelink.broker_issuer, item["broker_subject"])}):
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", key)
        before, snapshot = await identity_migration._inspect_in_conn(conn, user_id=uid,
            old_issuer=prelink.upstream_issuer, old_subject=item["upstream_subject"],
            new_issuer=prelink.broker_issuer, new_subject=item["broker_subject"], lock_user=True)
        await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
        state = before.state
        changed = False
        if verb in {"apply", "admit"} and state == "ready_to_link":
            identity_id = await conn.fetchval("""INSERT INTO external_identities
                (user_id,issuer,subject,username_snapshot,email_snapshot) VALUES($1,$2,$3,$4,$5) RETURNING id""",
                uid, prelink.broker_issuer, item["broker_subject"], snapshot.username, snapshot.email)
            await conn.execute("""INSERT INTO sso_identity_operation_bindings(operation_id,item_index,identity_id)
                VALUES($1,$2,$3) ON CONFLICT(operation_id,item_index) DO UPDATE SET identity_id=EXCLUDED.identity_id""",
                operation_id, index, identity_id)
            state, changed = "linked", True
        elif verb == "rollback":
            owned = await conn.fetchval("SELECT identity_id FROM sso_identity_operation_bindings WHERE operation_id=$1 AND item_index=$2", operation_id, index)
            if state == "linked" and owned is None:
                raise _error("sso_operation_binding_not_owned")
            if owned is not None:
                deleted = await conn.fetchval("""DELETE FROM external_identities WHERE id=$1 AND user_id=$2
                    AND issuer=$3 AND subject=$4 RETURNING id""", owned, uid, prelink.broker_issuer, item["broker_subject"])
                changed = deleted is not None
                if state == "linked" and not changed:
                    raise _error("sso_operation_binding_not_owned")
            state = "ready_to_link"
        confirmed = await _verify_item(row["provider_alias"], item)
        if confirmed != prelink or provider_fingerprint(await _provider(row["provider_alias"])) != row["current_provider_fingerprint"]:
            raise _error("identity_migration_prelink_changed")
        await _check_window(conn, row, request, actor_expires_at=actor_expires_at)
        result = {"schema_version": 1, "operation_id": str(operation_id), "nonce": str(request["nonce"]),
                  "verb": verb, "item_index": index, "user_id": str(uid), "state": state, "binding_changed": changed}
        await conn.execute("""INSERT INTO sso_identity_operation_requests(operation_id,nonce,request_sha256,result)
            VALUES($1,$2,$3,$4::jsonb)""", operation_id, request["nonce"], request_hash, _json(result))
        await emit_event(conn, "auth.sso_identity_operation_executed", actor_id=str(row["actor_id"]),
                         payload={"operation_id": str(operation_id), "verb": verb, "item_index": index,
                                  "user_id": str(uid), "binding_changed": changed, "request_sha256": request_hash})
        return result


async def status(operation_id: uuid.UUID) -> dict[str, Any]:
    pool = await get_pool()
    row = await pool.fetchrow("""SELECT operation_id,provider_alias,provider_revision,cohort_sha256,
        expires_at,retired_at,verbs FROM sso_identity_operations WHERE operation_id=$1""", operation_id)
    if row is None:
        raise _error("sso_operation_not_found", 404)
    return {"schema_version": 1, **{key: (value.isoformat() if isinstance(value, datetime) else str(value)
            if isinstance(value, uuid.UUID) else value) for key, value in dict(row).items()}}


async def retire(operation_id: uuid.UUID, *, actor_id: uuid.UUID) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow("SELECT operation_id FROM sso_identity_operations WHERE operation_id=$1 FOR UPDATE", operation_id)
        if row is None:
            raise _error("sso_operation_not_found", 404)
        await conn.execute("UPDATE sso_identity_operations SET retired_at=COALESCE(retired_at,NOW()) WHERE operation_id=$1", operation_id)
        await emit_event(conn, "auth.sso_identity_operation_retired", actor_id=str(actor_id),
                         payload={"operation_id": str(operation_id)})
    return await status(operation_id)
