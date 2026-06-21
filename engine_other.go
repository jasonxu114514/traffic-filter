//go:build !linux

package main

import "fmt"

func newNFQueueEngine(cfg AppConfig) (Engine, error) {
	return nil, fmt.Errorf("nfqueue engine is only supported on Linux")
}
