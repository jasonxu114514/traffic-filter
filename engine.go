package main

import (
	"context"
	"fmt"
)

type Engine interface {
	Run(context.Context) error
	Close() error
	Stats() EngineStats
}

type EngineStats struct {
	Total         uint64
	Passed        uint64
	HTTPBlocked   uint64
	TLSBlocked    uint64
	DNSPoisoned   uint64
	DNSBlocked    uint64
	IPBlocked     uint64
	IPPortBlocked uint64
	Malformed     uint64
}

func newEngine(cfg AppConfig) (Engine, error) {
	switch cfg.Engine {
	case "nfqueue":
		return newNFQueueEngine(cfg)
	case "af_xdp":
		return nil, fmt.Errorf("engine af_xdp is recognized but not implemented yet")
	case "xdp_fast_path":
		return nil, fmt.Errorf("engine xdp_fast_path is scaffolded but not implemented in the default build")
	default:
		return nil, fmt.Errorf("unknown engine %q", cfg.Engine)
	}
}
