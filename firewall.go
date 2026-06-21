package main

import "context"

type FirewallManager interface {
	Install(context.Context) error
	Cleanup(context.Context) error
}
