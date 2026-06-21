# Traffic Filter — NFQUEUE based network filter (pure Go)

BINARY := traffic-filter

.PHONY: all build clean install test help

all: build

# ─── Dependencies ──────────────────────────────────────────────────────────
deps:
	@echo "==> Install system dependencies (requires root):"
	@echo "  Ubuntu/Debian: sudo apt-get install iptables golang-go"
	@echo "  RHEL/CentOS:   sudo dnf install iptables golang"
	@echo "  Arch:          sudo pacman -S iptables go"
	@echo ""
	@echo "==> Check nfnetlink_queue module:"
	@echo "  lsmod | grep nfnetlink_queue"
	@echo "  sudo modprobe nfnetlink_queue"

# ─── Build ─────────────────────────────────────────────────────────────────
build:
	@echo "==> Downloading Go dependencies..."
	go mod tidy
	@echo "==> Building $(BINARY)..."
	go build -o $(BINARY) -v .

# ─── Clean ─────────────────────────────────────────────────────────────────
clean:
	@echo "==> Cleaning..."
	rm -f $(BINARY)

# ─── Install ───────────────────────────────────────────────────────────────
install: build
	@echo "==> Installing to /usr/local/bin..."
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

# ─── Test ──────────────────────────────────────────────────────────────────
test: build
	@echo "==> Test run (5 seconds)..."
	sudo timeout 5s ./$(BINARY) -mode local -domains "example.com" || true

# ─── Lint / fmt / vet ─────────────────────────────────────────────────────
fmt:
	go fmt ./...

vet:
	go vet ./...

# ─── Help ──────────────────────────────────────────────────────────────────
help:
	@echo "Traffic Filter (NFQUEUE mode) — Build targets:"
	@echo "  make build        Build Go binary"
	@echo "  make clean        Remove binary"
	@echo "  make install      Install to /usr/local/bin"
	@echo "  make test         Quick smoke test"
	@echo "  make fmt          Format Go source"
	@echo "  make vet          Run go vet"
	@echo ""
	@echo "Run:"
	@echo "  sudo ./$(BINARY) -mode local -domains \"a.com,b.com\""
	@echo "  sudo ./$(BINARY) -mode gateway -domains \"a.com\""
	@echo "  sudo ./$(BINARY) -mode all -domains \"a.com\" -block-ips \"1.2.3.4\""
