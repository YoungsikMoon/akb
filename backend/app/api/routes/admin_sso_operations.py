"""Explicit human grants and the separate bounded operation credential carrier."""

from datetime import datetime
from typing import Literal
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Response, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from app.api.routes.admin_auth import ProductAdminActor, get_current_product_admin, get_product_admin_mutation
from app.sso import identity_operations as operations
from app.sso.identity_migration import IdentityMigrationError
from app.sso.keycloak_admin import ProviderControlError
from app.models.admin_sso import SsoProviderView


class ValueLessRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                raise HTTPException(422, detail={"code": "sso_operation_request_invalid"}) from None
            except (IdentityMigrationError, ProviderControlError) as error:
                raise HTTPException(409, detail={"code": error.code}) from error
        return safe_handler


async def get_metadata_actor(request: Request, authorization: str | None = Header(default=None)):
    from app.api.routes.admin_sso import get_sso_provider_control_actor

    return await get_sso_provider_control_actor(request, authorization=authorization, csrf_header=None)


router = APIRouter(route_class=ValueLessRoute)


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OwnershipRequest(RequestModel):
    owner_id: str | None = Field(min_length=1, max_length=255)
    expected_revision: int = Field(ge=0, strict=True)
    expected_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    clear_emergency: bool = False


class CohortItem(RequestModel):
    existing_user_id: str
    upstream_subject: str = Field(repr=False)
    broker_subject: str = Field(repr=False)


Verb = Literal["preflight", "apply", "rollback", "admit", "configure", "enable", "disable"]


class GrantRequest(RequestModel):
    operation_id: uuid.UUID
    installation_id: uuid.UUID
    actor_id: uuid.UUID
    actor_token_id: uuid.UUID
    provider_alias: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,62}$")
    owner_id: str = Field(min_length=1, max_length=255)
    expected_provider_revision: int = Field(ge=1, strict=True)
    runtime_generation: int = Field(ge=1, strict=True)
    sso_session_epoch: uuid.UUID
    ttl_seconds: int = Field(ge=1, le=600, strict=True)
    verbs: list[Verb] = Field(min_length=1, max_length=7)
    cohort: list[CohortItem] = Field(max_length=25, repr=False)
    provider_payload_sha256: dict[str, str] = Field(default_factory=dict)


class ExecuteRequest(RequestModel):
    nonce: uuid.UUID
    verb: Verb
    item_index: int = Field(ge=0, strict=True)
    issued_at: datetime
    payload: dict | None = Field(default=None, repr=False)


class CapabilitiesResponse(RequestModel):
    schema_version: Literal[1]
    installation_id: uuid.UUID
    capabilities: list[str]
    max_ttl_seconds: int
    max_nonce_age_seconds: int
    realm_identity: dict[str, str] | None
    realm_identity_error: str | None


class OwnershipResponse(RequestModel):
    schema_version: Literal[1]
    provider_alias: str
    owner_id: str | None
    revision: int
    fingerprint: str
    drifted: bool
    emergency_disabled: bool


class GrantResponse(RequestModel):
    schema_version: Literal[1]
    operation_id: uuid.UUID
    credential: str = Field(repr=False)
    expires_at: datetime
    cohort_sha256: str
    provider_revision: int


class IdentityResultResponse(RequestModel):
    schema_version: Literal[1]
    operation_id: uuid.UUID
    nonce: uuid.UUID
    verb: Literal["preflight", "apply", "rollback", "admit"]
    item_index: int
    user_id: uuid.UUID
    state: Literal["ready_to_link", "linked"]
    binding_changed: bool


class ProviderResultResponse(RequestModel):
    schema_version: Literal[1]
    operation_id: uuid.UUID
    nonce: uuid.UUID
    verb: Literal["configure", "enable", "disable"]
    provider_revision: int
    provider: SsoProviderView


class StatusResponse(RequestModel):
    schema_version: Literal[1]
    operation_id: uuid.UUID
    provider_alias: str
    provider_revision: int
    cohort_sha256: str
    expires_at: datetime
    retired_at: datetime | None
    verbs: list[Verb]


@router.get("/admin/sso/operation-capabilities", response_model=CapabilitiesResponse)
async def operation_capabilities(_actor: ProductAdminActor = Depends(get_metadata_actor)):
    return await operations.capabilities()


@router.get("/admin/sso/providers/{alias}/ownership", response_model=OwnershipResponse)
async def read_ownership(alias: str, _actor: ProductAdminActor = Depends(get_metadata_actor)):
    return await operations.ownership(alias)


@router.put("/admin/sso/providers/{alias}/ownership", response_model=OwnershipResponse)
async def change_ownership(alias: str, request: OwnershipRequest,
                           actor: ProductAdminActor = Depends(get_product_admin_mutation)):
    return await operations.set_ownership(alias, **request.model_dump(), actor_id=uuid.UUID(str(actor.user_id)))


@router.post("/admin/sso/identity-operations", response_model=GrantResponse)
async def grant_operation(request: GrantRequest, response: Response, actor: ProductAdminActor = Depends(get_product_admin_mutation)):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await operations.grant(request.model_dump(), granted_by=uuid.UUID(str(actor.user_id)))


@router.post("/admin/sso/identity-operations/{operation_id}/execute", response_model=IdentityResultResponse | ProviderResultResponse)
async def execute_operation(operation_id: uuid.UUID, request: ExecuteRequest,
                            authorization: str | None = Header(default=None)):
    # This carrier is local to this one route. Cookies and regular bearer PATs
    # cannot become a bounded-operation credential, even when both are present.
    prefix = "AKB-Operation "
    if authorization is None or not authorization.startswith(prefix):
        raise HTTPException(401, detail={"code": "sso_operation_credential_invalid"})
    return await operations.execute(operation_id, authorization[len(prefix):], request.model_dump())


@router.get("/admin/sso/identity-operations/{operation_id}", response_model=StatusResponse)
async def operation_status(operation_id: uuid.UUID, _actor: ProductAdminActor = Depends(get_current_product_admin)):
    return await operations.status(operation_id)


@router.post("/admin/sso/identity-operations/{operation_id}/retire", response_model=StatusResponse)
async def retire_operation(operation_id: uuid.UUID, actor: ProductAdminActor = Depends(get_product_admin_mutation)):
    return await operations.retire(operation_id, actor_id=uuid.UUID(str(actor.user_id)))
