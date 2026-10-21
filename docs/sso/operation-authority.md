# Provider ownership and bounded identity operations

An installation can explicitly assign a provider alias to an external
controller. Unowned providers retain the standalone administrator and service
provider-management API. Assigning ownership is a human administrator ceremony,
not a side effect of a controller discovering an alias. No controller name,
private alias or external platform URL is built into this contract.

This API controls the currently configured SSO realm. It does not prepare a
different target realm while the installation still verifies a source issuer
or runs in local mode. That requires a separate management-only target contract;
these capabilities must not be counted as proof of pre-switch preparation.

## Discover and adopt

All paths below are relative to `/api/v1`. The existing administrator service
PAT can read `/admin/sso/operation-capabilities` and
`/admin/sso/providers/{alias}/ownership`. It cannot grant or retire operations or
assign ownership. Human calls use the product-admin session; mutations also
require the matching `X-AKB-Admin-CSRF` cookie/header proof.

Capabilities return `schema_version: 1`, the database-owned `installation_id`,
`max_ttl_seconds: 600`, `max_nonce_age_seconds: 300` and these behavior names:

- `sso.provider-ownership.v1`
- `sso.identity-operation.v1`
- `sso.enabled-exact-admission.v1`

`realm_identity` is `{realm_id, realm_name, issuer}` from an actual Admin REST
read of the configured realm. Missing permission, delegated management and
unavailable or invalid realms return `realm_identity: null` with a value-less
`realm_identity_error`. A controller must treat that as unknown. An issuer URL
or a bootstrap marker does not establish that the realm UUID survived a restore.
The normal management client needs `view-realm`, already part of the bundled
management role set. No arbitrary realm URL is accepted in the request.

Ownership readback contains `{schema_version, provider_alias, owner_id,
revision, fingerprint, drifted, emergency_disabled}`. For an absent alias,
`owner_id` is null and `revision` is initially zero. A human adopts or reserves
an alias with:

```json
{
  "owner_id": "controller-installation-id",
  "expected_revision": 0,
  "expected_fingerprint": "<fingerprint from live ownership GET>",
  "clear_emergency": false
}
```

Send this to `PUT /admin/sso/providers/{alias}/ownership`. Every successful
change advances the revision. `owner_id: null` explicitly releases ownership.
Fingerprint and revision mismatches fail rather than adopting a stale read.

Ordinary configure and enable requests for an owned alias are forbidden. A
human administrator may still disable it through the existing API. This records
`emergency_disabled`, advances the revision and fences earlier grants. Clearing
the emergency intent requires another explicit human CAS ownership request with
`clear_emergency: true`; a controller cannot clear it.

## Issue an operation

`POST /admin/sso/identity-operations` requires the human session and CSRF proof:

```json
{
  "operation_id": "<fresh UUID>",
  "installation_id": "<capabilities UUID>",
  "actor_id": "<existing service-user UUID>",
  "actor_token_id": "<existing service PAT UUID>",
  "provider_alias": "workforce",
  "owner_id": "controller-installation-id",
  "expected_provider_revision": 1,
  "runtime_generation": 1,
  "sso_session_epoch": "<current UUID>",
  "ttl_seconds": 600,
  "verbs": ["preflight", "apply", "rollback"],
  "cohort": [{
    "existing_user_id": "<existing AKB UUID>",
    "upstream_subject": "<exact opaque upstream subject>",
    "broker_subject": "<exact prelinked broker subject>"
  }],
  "provider_payload_sha256": {}
}
```

The response includes `schema_version`, `operation_id`, `expires_at`,
`cohort_sha256`, `provider_revision` and a one-time `credential` with no-store
headers. Only its hash is stored. Securely transfer the credential to the
intended controller; never place it in ordinary desired-state metadata or logs.
The operation is bound to the installation, actor/token, owner, provider
revision/fingerprint, runtime generation/epoch, verbs and at most 25 exact
cohort items. Both issuers are derived and frozen server-side. Grants fail for
local accounts, missing old bindings, different issuers and bindings belonging
to another AKB account. No email-based adoption or account merging occurs.

For provider-only operations, `cohort` is empty and verbs are selected from
`configure`, `enable`, `disable`. `provider_payload_sha256` must contain exactly
one digest per granted provider verb. A configure payload uses the existing
provider configuration request fields; toggle payloads are exactly `{}`.
The digest is SHA-256 of UTF-8 JSON with lexicographically sorted ASCII field
keys, no whitespace and preserved Unicode (`ensure_ascii=False`). Payloads
contain strings/null, so numeric canonicalization is not involved. Secrets are
not included in a grant, operation row, result or audit event, only in the
execution request to the existing provider security profile.

## Execute, retry and retire

Send `POST /admin/sso/identity-operations/{operation_id}/execute` with
`Authorization: AKB-Operation <credential>`:

```json
{
  "nonce": "<fresh UUID>",
  "issued_at": "2026-10-21T00:00:00Z",
  "verb": "apply",
  "item_index": 0,
  "payload": null
}
```

Identity verbs use a cohort index. Provider verbs require index zero and the
exact payload whose digest the human approved. Ordinary PATs and browser
cookies cannot execute this route. This dedicated header carrier does not use
browser CSRF. A nonce is valid for at most 300 seconds and never beyond the
operation's expiry. The same nonce and request digest return the stored result;
changing the digest is a conflict. Retirement, revoked/expired actor tokens,
granting-admin demotion, runtime changes, ownership changes and drift reject
both new writes and credential-based replays.

`apply` and `rollback` require the provider disabled. `admit` is a separate,
explicitly granted verb for an enabled provider and the same proven exact
upstream cohort. It never disables a provider to admit one person. Preflight
does not mutate. An operation rolls back only a binding it actually inserted,
identified by that row's UUID. Existing AKB UUIDs, PATs, Vault ownership and ACLs
are preserved. AKB mutation, nonce receipt, ownership of the inserted binding
and audit event commit atomically; a changed Keycloak postcheck rolls them back.

Provider execution advances both the ownership revision and the operation's
effective revision. Its original grant revision remains in the journal. A raw
Keycloak success followed by a process/database failure can leave observable
drift without a committed receipt. This is an explicit reconciliation state:
do not blindly repeat the write or re-enable the provider. A human must inspect
and adopt the live fingerprint before issuing another operation.

Human administrators inspect a secret-free operation with
`GET /admin/sso/identity-operations/{id}` and retire it with
`POST /admin/sso/identity-operations/{id}/retire`. Retirement is idempotent and
retains the journal. No automatic Keycloak user/link deletion is performed.

## Trust boundary and artifact evidence

Full Keycloak realm administrators can bypass these API guards. The guarantee
is API ownership enforcement plus detection of visible raw configuration drift,
not an immutable realm policy. Masked secrets prevent a readback fingerprint
from detecting every out-of-band secret replacement. Preserve emergency intent
and require independent login/secret-revision evidence for transition finality.

The existing machine account-governance API is still trusted to project roles,
activate and offboard already admitted AKB IDs. Approved machine token issuers
retain their explicitly configured issuance authority. The bounded operation
credential does not isolate the installation from complete compromise of those
broader trusted authorities. Machine account projection cannot add a new
binding to an existing AKB ID outside the bounded operation; an exact existing
binding can still be refreshed. Fresh admissions under the exact configured
issuer remain distinct from migration. Human standalone administration remains.

Machine administrator SQL now uses its ordinary PostgreSQL user/token role;
`is_admin` alone does not delegate the backend database role. Granted Vault SQL
continues through RoleSync. Live human system administrators retain their
existing full SQL trust boundary.

Version labels alone do not establish support. Genuine `backend-v0.14.2`
(`b28b345e687ae35441abec545961c9d09b39ea18`) predates the provider-admin route.
Snapshot `9c705f0a03360c9ac788341dfc56f367bdda9b06` is 147 commits later.
Candidate admission must combine immutable artifact/source provenance with
behavior fixtures. Source-native PostgreSQL/HTTP tests establish this contract's
AKB behavior; their substituted Keycloak readbacks are not proof of live
Keycloak permissions or a particular deployed image.
