#!/bin/bash
set -e
echo "=== Traffic Filter Build (AF_PACKET) ==="

echo "--- go mod tidy ---"
go mod tidy
echo "--- go build ---"
go build -o traffic-filter -v .
echo ""
echo "=== Build complete ==="
echo "Run: sudo ./traffic-filter -iface eth0 -domains \"pornhub.com,www.pornhub.com\" -dns-mode poison"
