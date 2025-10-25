#!/bin/bash
echo "Testing Hexstrike server health..."
curl -s http://localhost:8888/health | python3 -m json.tool || echo "Server is not running. Start it with ./start_server.sh"
