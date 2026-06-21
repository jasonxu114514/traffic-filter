# Traffic Filter — AF_PACKET based network filter (no eBPF)

BINARY := traffic-filter

.PHONY: all build clean install test help

all: build

build:
	go mod tidy
	go build -o $(BINARY) -v .

clean:
	rm -f $(BINARY)

install: build
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

test: build
	sudo timeout 5s ./$(BINARY) -iface eth0 -domains "example.com" -dns-mode poison || true

fmt:
	go fmt ./...

vet:
	go vet ./...

help:
	@echo "Traffic Filter (AF_PACKET)"
	@echo "  make build        Build binary"
	@echo "  make clean        Remove binary"
	@echo "  make install      Install to /usr/local/bin"
	@echo "  make test         Quick test"
	@echo ""
	@echo "Run:"
	@echo "  sudo ./traffic-filter -iface eth0 -domains \"a.com,b.com\" -dns-mode poison"
	@echo "  sudo ./traffic-filter -iface eth0 -block-ips \"1.2.3.4\""
	@echo "  sudo ./traffic-filter -iface eth0 -block-ip-ports \"1.2.3.4:80:tcp\""
