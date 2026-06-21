//go:build !linux

package main

import "fmt"

func newFirewallManager(cfg NFQueueConfig) (FirewallManager, error) {
	return nil, fmt.Errorf("firewall management is only supported on Linux")
}
