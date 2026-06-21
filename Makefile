# Traffic Filter — XDP/eBPF based network filter (pure Go + embedded BPF)

BINARY := traffic-filter
BPF_SRC := bpf/filter.bpf.c
BPF_OBJ := bpf/filter.bpf.o

.PHONY: all build clean install test help bpf

all: build

# ─── Dependencies ──────────────────────────────────────────────────────────
deps:
	@echo "==> Install system dependencies (requires root):"
	@echo "  Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev golang-go"
	@echo "  For vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"

# ─── Build BPF ─────────────────────────────────────────────────────────────
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "==> Compiling eBPF program..."
	clang -O2 -g -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "==> eBPF program compiled: $(BPF_OBJ)"

# ─── Build Go ──────────────────────────────────────────────────────────────
build: $(BPF_OBJ)
	@echo "==> Downloading Go dependencies..."
	go mod tidy
	@echo "==> Building $(BINARY) (embedding eBPF bytecode)..."
	go build -o $(BINARY) -v .
	@echo "==> Build complete: $(BINARY)"

# ─── Clean ─────────────────────────────────────────────────────────────────
clean:
	@echo "==> Cleaning..."
	rm -f $(BINARY)
	rm -f $(BPF_OBJ)

# ─── Install ───────────────────────────────────────────────────────────────
install: build
	@echo "==> Installing to /usr/local/bin..."
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

# ─── Test ──────────────────────────────────────────────────────────────────
test: build
	@echo "==> Test (requires root and network interface)..."
	@echo "Run: sudo ./$(BINARY) -iface eth0"

# ─── Help ──────────────────────────────────────────────────────────────────
help:
	@echo "Traffic Filter (XDP/eBPF mode) — Build targets:"
	@echo "  make bpf          Compile eBPF program only"
	@echo "  make build        Build Go binary (with embedded eBPF)"
	@echo "  make clean        Remove build artifacts"
	@echo "  make install      Install to /usr/local/bin"
	@echo ""
	@echo "Run:"
	@echo "  sudo ./$(BINARY) -iface eth0"
	@echo "  sudo ./$(BINARY) -iface ens18 -debug"
