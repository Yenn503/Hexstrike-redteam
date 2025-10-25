#!/bin/bash
# Hexstrike Red Team - Test Server Health
# Tests if the MCP server is running and responding

echo "Testing Hexstrike server health..."
echo ""

RESPONSE=$(curl -s http://localhost:8888/health 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Server is running!"
    echo ""
    echo "Server Response:"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
else
    echo "✗ Server is not running or not responding."
    echo ""
    echo "To start the server, run:"
    echo "  ./start_server.sh"
fi
echo ""
