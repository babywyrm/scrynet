"""
MCP Server Authentication Middleware

Bearer token authentication for the Starlette SSE server.
Token is read from AGENTSMITH_MCP_TOKEN environment variable.
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_server.config import MCP_TOKEN

logger = logging.getLogger(__name__)

# Paths that bypass auth (health checks, etc.)
PUBLIC_PATHS = {"/health", "/ready"}


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Authorization: Bearer <token> on all non-public endpoints."""

    async def dispatch(self, request: Request, call_next):
        # Allow public endpoints without auth
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Validate bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning(f"Missing bearer token from {request.client.host}")
            return JSONResponse(
                {"error": "Authorization header with Bearer token required"},
                status_code=401,
            )

        token = auth_header[7:]  # Strip "Bearer "
        if token != MCP_TOKEN:
            logger.warning(f"Invalid token from {request.client.host}")
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=403,
            )

        return await call_next(request)
