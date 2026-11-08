"""DRF exception handler. Every error comes back as JSON with a readable `detail`."""
from __future__ import annotations

import logging

from rest_framework.response import Response
from rest_framework.views import exception_handler

log = logging.getLogger("aether.api")


def handler(exc, context):
    resp = exception_handler(exc, context)
    if resp is not None:
        return resp
    view = context.get("view")
    log.exception("unhandled error in %s", type(view).__name__ if view else "?", exc_info=exc)
    return Response({"detail": f"Internal error ({type(exc).__name__}). Details are in the AetherEDR terminal."}, status=500)
