#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building..."
npm run build

echo ""
echo "==> Testing MCP server via stdio..."

WHOIS_DOMAIN="${1:-google.com}"

# Send JSON-RPC messages to the MCP server via stdin:
# 1. initialize
# 2. initialized notification
# 3. tools/list
# 4. tools/call (whois_domain)
node dist/index.js <<EOF | jq -c .
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whois_domain","arguments":{"domain":"${WHOIS_DOMAIN}"}}}
EOF

echo ""
echo "==> Done."
