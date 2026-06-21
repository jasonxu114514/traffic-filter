#!/bin/bash
set -e

echo "=== Traffic Filter Build ==="

# 1. Check dependencies
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] $1 not found — install it first"
        exit 1
    fi
}
check_dep clang
check_dep go
if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then
    echo "[ERROR] libbpf-dev not installed"
    echo "  Ubuntu: sudo apt-get install libbpf-dev"
    exit 1
fi
echo "[OK] dependencies"

# 2. Compile eBPF
echo "--- compiling eBPF ---"
cd bpf
clang -O2 -target bpf -c traffic_filter.c -o traffic_filter.o \
    -I/usr/include -I/usr/include/x86_64-linux-gnu -Wall -Werror
cd ..
echo "[OK] bpf/traffic_filter.o"

# 3. Generate Go bindings
echo "--- generating Go bindings ---"
cd pkg/filter
go generate ./...
cd ../..
echo "[OK] bindings"

# 4. Download Go modules
echo "--- go mod tidy ---"
go mod tidy
echo "[OK] modules"

# 5. Build Go binary
echo "--- building ---"
go build -o traffic-filter -v ./cmd/traffic-filter
echo "[OK] traffic-filter"

echo ""
echo "=== Build complete ==="
echo "Run: sudo ./traffic-filter -iface eth0 -domains \"pornhub.com,www.pornhub.com\" -dns-mode poison"
echo "For IP blocking: add -block-ips \"1.2.3.4,5.6.7.8\""
echo "For IP:Port:    add -block-ip-ports \"1.2.3.4:80:tcp,1.2.3.4:443:tcp\""
