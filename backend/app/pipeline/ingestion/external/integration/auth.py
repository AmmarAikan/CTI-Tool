from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Protocol


class AuthenticationError(PermissionError):
    pass


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    roles: frozenset[str]


class Authenticator(Protocol):
    def authenticate(self, bearer_token: str) -> Principal: ...


class Authorizer(Protocol):
    def require(self, principal: Principal, permission: str) -> None: ...


ROLE_PERMISSIONS = {
    "viewer": frozenset({"health:read", "sources:read", "jobs:read", "exports:read", "reviews:read"}),
    "operator": frozenset({"health:read", "sources:read", "jobs:read", "jobs:create", "jobs:cancel", "manual:create", "manual:preview", "manual:approve", "manual:reject", "exports:read", "reviews:read", "sources:disable", "sources:request_enable"}),
    "source_approver": frozenset({"health:read", "sources:read", "jobs:read", "sources:request_enable", "sources:disable"}),
    "dark_web_approver": frozenset({"health:read", "sources:read", "jobs:read", "sources:request_enable", "sources:disable", "dark_web:approve"}),
    "admin": frozenset({"*"}),
}


class RoleAuthorizer:
    def require(self, principal: Principal, permission: str) -> None:
        granted = set().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in principal.roles))
        if "*" not in granted and permission not in granted:
            raise AuthorizationError("operation is not permitted")


class StaticTokenAuthenticator:
    """Local-only token adapter; replace with the deployment identity provider."""

    def __init__(self, token: str, *, subject: str = "local-dashboard", roles: frozenset[str] = frozenset({"operator"})) -> None:
        if not token: raise ValueError("a non-empty local API token is required")
        self._token, self._principal = token, Principal(subject, roles)

    def authenticate(self, bearer_token: str) -> Principal:
        if not bearer_token or not hmac.compare_digest(self._token, bearer_token):
            raise AuthenticationError("invalid internal API credentials")
        return self._principal
