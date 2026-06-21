BINARY := middle-filter
BPF_SRC := bpf/filter.bpf.c
BPF_OBJ := bpf/filter.bpf.o

CLANG ?= clang
GO ?= go

.PHONY: all bpf build test clean run help

all: build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ)

build: $(BPF_OBJ)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -o $(BINARY) .

test: $(BPF_OBJ)
	$(GO) test ./...

clean:
	rm -f $(BINARY) $(BPF_OBJ)

run: build
	sudo ./$(BINARY) -config config.json

help:
	@echo "Targets:"
	@echo "  make bpf      Compile XDP/eBPF object"
	@echo "  make build    Build Linux x86_64 binary with embedded BPF"
	@echo "  make test     Run Go tests after compiling BPF object"
	@echo "  make clean    Remove build outputs"
	@echo ""
	@echo "Example:"
	@echo "  sudo ./$(BINARY) -config config.json"
