# Traffic Filter — eBPF/XDP based network filter

BINARY    := traffic-filter
BPF_SRC   := bpf/traffic_filter.c
BPF_OBJ   := bpf/traffic_filter.o
CMD_DIR   := ./cmd/traffic-filter

.PHONY: all build clean install test help

all: build

# ─── Dependencies ──────────────────────────────────────────────────────────
deps:
	@echo "==> Install system dependencies (requires root):"
	@echo "  Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev linux-headers-\$$(uname -r) golang-go"
	@echo "  RHEL/CentOS:   sudo dnf install clang llvm libbpf-devel kernel-devel golang"
	@echo "  Arch:          sudo pacman -S clang llvm libbpf linux-headers go"

# ─── Build ─────────────────────────────────────────────────────────────────
$(BPF_OBJ): $(BPF_SRC)
	@echo "==> Compiling eBPF program..."
	clang -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ) \
		-I/usr/include \
		-Wall -Werror

build: $(BPF_OBJ)
	@echo "==> Generating Go bindings + downloading dependencies..."
	cd pkg/filter && go generate ./...
	go mod tidy
	@echo "==> Building $(BINARY)..."
	go build -o $(BINARY) $(CMD_DIR)

# ─── Clean ─────────────────────────────────────────────────────────────────
clean:
	@echo "==> Cleaning..."
	rm -f $(BINARY)
	rm -f $(BPF_OBJ)
	rm -f pkg/filter/bpf_bpfel.go pkg/filter/bpf_bpfel.o
	rm -f pkg/filter/bpf_bpfeb.go pkg/filter/bpf_bpfeb.o

# ─── Install ───────────────────────────────────────────────────────────────
install: build
	@echo "==> Installing to /usr/local/bin..."
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

# ─── Test ──────────────────────────────────────────────────────────────────
test: build
	@echo "==> Test run (5 seconds) on eth0..."
	sudo timeout 5s ./$(BINARY) -iface eth0 -domains "example.com" -dns-mode poison || true

# ─── Lint / fmt / vet ─────────────────────────────────────────────────────
lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

# ─── Help ──────────────────────────────────────────────────────────────────
help:
	@echo "Traffic Filter — Build targets:"
	@echo "  make build        Compile eBPF + Go binary"
	@echo "  make clean        Remove build artifacts"
	@echo "  make install      Install to /usr/local/bin"
	@echo "  make test         Quick smoke test"
	@echo "  make fmt          Format Go source"
	@echo "  make vet          Run go vet"
	@echo ""
	@echo "Run:"
	@echo "  sudo ./$(BINARY) -iface <nic> -domains <a,b> [-block-ips <ip,...>] [-block-ip-ports <ip:port:proto,...>] [-dns-mode drop|poison] [-ip-mode tcp,udp,icmp]"
