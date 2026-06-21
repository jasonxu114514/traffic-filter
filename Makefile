BINARY := middle-filter
BPF_SRC := bpf/filter.bpf.c
BPF_OBJ := bpf/filter.bpf.o

CLANG ?= clang
GO ?= go

.PHONY: all bpf build build-xdp test clean run help

all: build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ)

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -o $(BINARY) .

build-xdp: $(BPF_OBJ)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags xdp -trimpath -o $(BINARY) .

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY) $(BPF_OBJ)

run: build
	sudo ./$(BINARY) -config config.json

help:
	@echo "Targets:"
	@echo "  make build      Build Linux x86_64 NFQUEUE binary"
	@echo "  make build-xdp  Experimental XDP-tagged build"
	@echo "  make bpf        Compile XDP/eBPF object"
	@echo "  make test       Run Go tests"
	@echo "  make clean      Remove build outputs"
	@echo ""
	@echo "Example:"
	@echo "  sudo ./$(BINARY) -config config.json"
