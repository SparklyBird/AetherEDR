"""API key auth. Two keys, both created on first run in the data folder.

api_key     - the console and scripts. Full access.
ingest_key  - remote agents. It can only post collected data to /api/ingest/, so a stolen agent key
              cannot read alerts, memory or run response actions.
"""
from __future__ import annotations

import hmac

from django.conf import settings
from rest_framework import authentication, exceptions, permissions


class ApiUser:
    is_authenticated = True
    is_active = True
    username = "aether-operator"
    pk = 0
    is_operator = True


class AgentUser(ApiUser):
    username = "aether-agent"
    is_operator = False


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class ApiKeyAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        key = request.headers.get("X-Aether-Key")
        if not key:
            header = request.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                key = header[7:].strip()
        if not key:
            return None
        operator = _same(key, settings.API_KEY)
        agent = _same(key, settings.INGEST_KEY)      # both are always compared, so timing says nothing about which
        if operator:
            return (ApiUser(), None)
        if agent:
            return (AgentUser(), None)
        raise exceptions.AuthenticationFailed("invalid API key")

    def authenticate_header(self, request):
        return "Bearer"


class IsOperator(permissions.BasePermission):
    """Everything except ingest needs the full key."""

    message = "This key can only send agent data. Use the API key for this."

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and getattr(request.user, "is_operator", False))


class IsAgentOrOperator(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
