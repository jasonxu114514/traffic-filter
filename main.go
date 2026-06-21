package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {
	// CLI flags
	iface := flag.String("iface", "", "Network interface (required)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Set log level
	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// Check root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (use sudo)")
	}

	// Check interface
	if *iface == "" {
		log.Fatal("Interface is required (-iface)")
	}

	log.WithField("interface", *iface).Info("Traffic Filter starting (XDP/eBPF mode)")

	// Load XDP filter
	xdpFilter, err := NewXDPFilter(*iface)
	if err != nil {
		log.WithError(err).Fatal("failed to load XDP filter")
	}
	defer xdpFilter.Close()

	// Block common ports
	// HTTP
	if err := xdpFilter.BlockPort(80); err != nil {
		log.WithError(err).Warn("failed to block port 80")
	}
	// HTTPS
	if err := xdpFilter.BlockPort(443); err != nil {
		log.WithError(err).Warn("failed to block port 443")
	}
	// DNS
	if err := xdpFilter.BlockPort(53); err != nil {
		log.WithError(err).Warn("failed to block port 53")
	}

	log.Info("Ports 80, 443, 53 blocked. Press Ctrl+C to stop.")

	// Print stats periodically
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			total, blocked, passed, err := xdpFilter.GetStats()
			if err != nil {
				log.WithError(err).Warn("failed to get stats")
				continue
			}
			log.WithFields(log.Fields{
				"total":   total,
				"blocked": blocked,
				"passed":  passed,
			}).Info("XDP stats")
		}
	}()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")

	// Print final stats
	total, blocked, passed, _ := xdpFilter.GetStats()
	log.WithFields(log.Fields{
		"total_packets":   total,
		"blocked_packets": blocked,
		"passed_packets":  passed,
	}).Info("final statistics")
}
