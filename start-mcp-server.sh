#!/bin/bash
# Start the MCP DAP Server
# Runs the Python MCP server that bridges AI tools to DAP debuggers via stdio.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/mcp-dap-server"

exec python3 -m mcp_dap_server.server "$@"
