"""Protected host input and active runtime gates, without a database."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.standalone_sso_bootstrap import MANAGEMENT_REALM_ROLES, StandaloneSSOReadback
from app.sso.prepare_target_host import HostPreparationInput, canonical, digest, protected_read, protected_write
from app.sso.adopt_prepared_target import PreparedTargetReceipt, validate_runtime_binding


def preparation(**changes):
    values = dict(operation_id=uuid4(), org_id=uuid4(), target_id=uuid4(), realm_id=uuid4(), session_epoch=uuid4(),
                  realm_name="akb", issuer="https://identity.example/realms/akb", internal_url="http://keycloak:8080",
                  akb_public_url="https://workspace.example", backchannel_logout_uri="http://backend:8000/api/v1/auth/keycloak/backchannel-logout",
                  bootstrap_client_id="bootstrap-once", bootstrap_client_secret="host-bootstrap-unique-material",
                  management_client_id="akb-sso-manager", management_client_secret="manager-unique-material",
                  api_client_id="akb-web", api_client_secret="web-unique-material", admin_client_id="akb-admin",
                  admin_client_secret="admin-unique-material", browser_session_key="browser-unique-material-of-32-bytes-or-more",  # pragma: allowlist secret
                  product_admin_subject=uuid4(), product_admin_email="recovery@example.invalid",
                  product_admin_password="native-unique-credential", cohort=[])  # pragma: allowlist secret
    return HostPreparationInput(**(values | changes))


def bound_fixture():
    p = preparation()
    rb = StandaloneSSOReadback(str(p.realm_id), str(p.product_admin_subject), "admin", "manager", "web", "kid", 3072, 1,
                              MANAGEMENT_REALM_ROLES, MANAGEMENT_REALM_ROLES, "pwd", 0)
    target = dict(target_id=str(p.target_id), realm_id=str(p.realm_id), realm_name=p.realm_name, issuer=p.issuer,
                  internal_url=p.internal_url, management_client_id=p.management_client_id,
                  management_client_secret=p.management_client_secret.get_secret_value(), session_epoch=str(p.session_epoch),
                  verify_ssl=True)
    descriptor = canonical({"schema_version": 1, "targets": [target]})
    values = p.model_dump(mode="json", exclude={"verify_ssl", "bootstrap_client_secret", "management_client_secret", "api_client_secret",
        "admin_client_secret", "browser_session_key", "product_admin_password", "product_admin_subject"})
    values.update(schema_version=1, product_admin_username=p.product_admin_username, config_sha256=digest(descriptor),
                  active_credentials_sha256=digest(canonical({"api_client_secret": p.api_client_secret.get_secret_value(),
                      "admin_client_secret": p.admin_client_secret.get_secret_value(),
                      "management_client_secret": p.management_client_secret.get_secret_value(),
                      "browser_session_key": p.browser_session_key.get_secret_value()})),
                  input_binding_sha256="a" * 64, cohort_sha256=digest(canonical([])), profile="bundled-keycloak-v6",
                  readback=asdict(rb), prepared_at=datetime.now(timezone.utc), authority_retired_at=datetime.now(timezone.utc),
                  retirement_evidence={"new_token_denied": True, "prior_token_master_call_denied": True})
    receipt = PreparedTargetReceipt(**values)
    settings = SimpleNamespace(require_auth_mode=lambda: "sso", keycloak_enabled=True, keycloak_public_client=False,
        sso_prepared_target_id=str(p.target_id), sso_session_epoch=p.session_epoch, keycloak_server_url="https://identity.example",
        keycloak_internal_url=p.internal_url, keycloak_realm=p.realm_name, keycloak_client_id=p.api_client_id,
        keycloak_admin_client_id=p.admin_client_id, keycloak_management_client_id=p.management_client_id,
        keycloak_client_secret=p.api_client_secret.get_secret_value(), keycloak_admin_client_secret=p.admin_client_secret.get_secret_value(),
        keycloak_management_client_secret=p.management_client_secret.get_secret_value(), keycloak_verify_ssl=True,
        sso_browser_session_encryption_key=p.browser_session_key.get_secret_value(), public_base_url=p.akb_public_url,
        keycloak_backchannel_logout_uri_effective=p.backchannel_logout_uri, sso_local_realm_self_registration=False)
    return receipt, descriptor, settings


def test_runtime_accepts_exact_binding_with_no_bootstrap_material():
    receipt, descriptor, settings = bound_fixture()
    spec = validate_runtime_binding(receipt, descriptor, settings)
    assert spec.bootstrap_client_secret == spec.product_admin_password == ""


@pytest.mark.parametrize("field,value", [("sso_prepared_target_id", str(uuid4())), ("keycloak_server_url", "https://source.example"),
    ("keycloak_internal_url", "http://source:8080"), ("keycloak_client_id", "other"), ("keycloak_management_client_secret", "wrong"),
    ("sso_browser_session_encryption_key", "wrong"), ("keycloak_enabled", False), ("sso_session_epoch", uuid4())])
def test_runtime_refuses_unswitched_or_changed_runtime(field, value):
    receipt, descriptor, settings = bound_fixture()
    setattr(settings, field, value)
    with pytest.raises(RuntimeError):
        validate_runtime_binding(receipt, descriptor, settings)


@pytest.mark.parametrize("change", [{"realm_id": uuid4()}, {"profile": "bundled-keycloak-v5"},
                                  {"retirement_evidence": {"new_token_denied": True}}, {"cohort_sha256": "0" * 64}])
def test_runtime_refuses_receipt_mismatch(change):
    receipt, descriptor, settings = bound_fixture()
    with pytest.raises(RuntimeError):
        validate_runtime_binding(receipt.model_copy(update=change), descriptor, settings)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666])
def test_protected_input_requires_exact_private_permissions(tmp_path, mode):
    path = tmp_path / "input.json"
    path.write_text("{}")
    path.chmod(mode)
    with pytest.raises(RuntimeError):
        protected_read(path)


def test_atomic_private_output_and_symlink_refusal(tmp_path):
    path = tmp_path / "input.json"
    protected_write(path, {"a": 1})
    assert json.loads(protected_read(path)) == {"a": 1}
    assert path.stat().st_mode & 0o777 == 0o600
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        protected_read(alias)


def test_cohort_duplicate_or_large_or_recovery_collision_refused():
    member = dict(akb_user_id=uuid4(), broker_subject=uuid4(), broker_username="user", provider_alias="platform",
                  upstream_issuer="https://upstream.example/realms/platform", upstream_subject="opaque")
    with pytest.raises(ValueError):
        preparation(cohort=[member, member])
    with pytest.raises(ValueError):
        preparation(cohort=[member] * 26)
    with pytest.raises(ValueError):
        preparation(realm_name="master")


def test_host_leaf_imports_no_database_or_active_settings():
    path = Path(__file__).resolve().parents[1] / "app/sso/prepare_target_host.py"
    source = path.read_text()
    assert "from app.db" not in source and "from app.config" not in source
