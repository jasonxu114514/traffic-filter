package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const defaultConfigPath = "config.json"

func main() {
	if err := run(); err != nil {
		log.WithError(err).Fatal("middle filter failed")
	}
}

func run() error {
	configPath := flag.String("config", defaultConfigPath, "path to JSON config file")
	flag.Parse()

	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flag.Args(), " "))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must run as root or with CAP_NET_ADMIN")
	}

	engine, err := newEngine(cfg)
	if err != nil {
		return err
	}
	defer engine.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(cfg.statsEvery)
	defer ticker.Stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- engine.Run(ctx)
	}()

	log.WithField("engine", cfg.Engine).Info("middle filter active; press Ctrl+C to stop")

	for {
		select {
		case <-ticker.C:
			printStats(engine.Stats())
		case err := <-errCh:
			if err != nil {
				return err
			}
			printStats(engine.Stats())
			return nil
		case <-ctx.Done():
			err := <-errCh
			if err != nil {
				return err
			}
			printStats(engine.Stats())
			return nil
		}
	}
}

func printStats(stats EngineStats) {
	log.WithFields(log.Fields{
		"total":           stats.Total,
		"passed":          stats.Passed,
		"http_blocked":    stats.HTTPBlocked,
		"tls_blocked":     stats.TLSBlocked,
		"dns_poisoned":    stats.DNSPoisoned,
		"dns_blocked":     stats.DNSBlocked,
		"ip_blocked":      stats.IPBlocked,
		"ip_port_blocked": stats.IPPortBlocked,
		"malformed":       stats.Malformed,
	}).Info("filter stats")
}
