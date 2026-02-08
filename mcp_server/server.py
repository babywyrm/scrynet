"""
Agent Smith MCP Server

SSE-based Model Context Protocol server exposing Agent Smith's
scanning and analysis tools over HTTP.

Usage:
    python3 -m mcp_server                    # default port 2266
    python3 -m mcp_server --port 3000        # custom port
    python3 -m mcp_server --no-auth          # disable auth (dev only)
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp.server.lowlevel import Server as MCPServer
from mcp import types as mcp_types

from mcp_server.config import MCP_HOST, MCP_PORT, MCP_TOKEN, PROJECT_ROOT
from mcp_server.tools import TOOL_DEFINITIONS, TOOL_HANDLERS

logger = logging.getLogger("agentsmith.mcp")


# ---------------------------------------------------------------------------
# MCP Server setup
# ---------------------------------------------------------------------------

def create_mcp_app() -> MCPServer:
    """Create and configure the MCP server with all Agent Smith tools."""
    app = MCPServer("agentsmith")

    @app.list_tools()
    async def list_tools() -> list[mcp_types.Tool]:
        return [
            mcp_types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["input_schema"],
            )
            for t in TOOL_DEFINITIONS
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[mcp_types.TextContent]:
        handler = TOOL_HANDLERS.get(name)
        if not handler:
            return [mcp_types.TextContent(
                type="text",
                text=f'{{"error": "Unknown tool: {name}"}}',
            )]

        try:
            result = await handler(arguments)
        except ValueError as e:
            result = f'{{"error": "{e}"}}'
        except Exception as e:
            logger.exception(f"Tool '{name}' failed")
            result = f'{{"error": "Internal error: {type(e).__name__}: {e}"}}'

        return [mcp_types.TextContent(type="text", text=result)]

    return app


# ---------------------------------------------------------------------------
# SSE transport + Starlette app
# ---------------------------------------------------------------------------

def create_starlette_app(mcp_app: MCPServer, require_auth: bool = True):
    """Build the Starlette ASGI app with SSE transport, auth, and health."""
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp_app.run(
                streams[0], streams[1], mcp_app.create_initialization_options()
            )
        return Response()

    async def handle_health(request: Request):
        return JSONResponse({
            "status": "healthy",
            "service": "agentsmith-mcp",
            "tools": len(TOOL_DEFINITIONS),
        })

    async def handle_ready(request: Request):
        scanner_ok = (PROJECT_ROOT / "scanner").is_file()
        return JSONResponse({
            "status": "ready" if scanner_ok else "degraded",
            "scanner": "available" if scanner_ok else "missing",
        })

    routes = [
        Route("/health", endpoint=handle_health, methods=["GET"]),
        Route("/ready", endpoint=handle_ready, methods=["GET"]),
        Route("/sse", endpoint=handle_sse, methods=["GET"]),
        Mount("/messages/", app=sse.handle_post_message),
    ]

    app = Starlette(debug=False, routes=routes)

    # Add auth middleware if enabled
    if require_auth:
        from mcp_server.auth import BearerAuthMiddleware
        app.add_middleware(BearerAuthMiddleware)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Agent Smith MCP Server",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--port", type=int, default=MCP_PORT,
        help=f"Port to listen on (default: {MCP_PORT})",
    )
    parser.add_argument(
        "--host", type=str, default=MCP_HOST,
        help=f"Host to bind to (default: {MCP_HOST})",
    )
    parser.add_argument(
        "--no-auth", action="store_true",
        help="Disable bearer token authentication (dev only, NOT for production)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Auth check
    require_auth = not args.no_auth
    if require_auth and not MCP_TOKEN:
        logger.error(
            "AGENTSMITH_MCP_TOKEN environment variable is required.\n"
            "Set it with: export AGENTSMITH_MCP_TOKEN=your-secret-token\n"
            "Or use --no-auth for development (insecure)."
        )
        sys.exit(1)

    if not require_auth:
        logger.warning("Authentication DISABLED. Do not use in production.")

    # Build and run
    mcp_app = create_mcp_app()
    starlette_app = create_starlette_app(mcp_app, require_auth=require_auth)

    logger.info(f"Agent Smith MCP Server starting on {args.host}:{args.port}")
    logger.info(f"SSE endpoint: http://{args.host}:{args.port}/sse")
    logger.info(f"Health check: http://{args.host}:{args.port}/health")
    logger.info(f"Tools available: {len(TOOL_DEFINITIONS)}")
    logger.info(f"Auth: {'enabled' if require_auth else 'DISABLED'}")

    import uvicorn
    uvicorn.run(starlette_app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
