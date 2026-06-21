package main

import (
	"flag"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {
	// CLI flags
	iface := flag.String("iface", "", "Network interface (required)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	ports := flag.String("ports", "80,443,53", "Ports to block (comma-separated)")
	domains := flag.String("domains", "", "Domains to block (comma-separated)")
	dnsMode := flag.String("dns-mode", "drop", "DNS mode: drop or poison")
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

	// Block ports
	portList := strings.Split(*ports, ",")
	for _, portStr := range portList {
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			log.WithError(err).Warnf("invalid port: %s", portStr)
			continue
		}
		if err := xdpFilter.BlockPort(uint16(port)); err != nil {
			log.WithError(err).Warnf("failed to block port %d", port)
		}
	}
	log.Infof("Ports %s blocked", *ports)

	// Block domains
	if *domains != "" {
		domainList := strings.Split(*domains, ",")
		for _, domain := range domainList {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			if err := xdpFilter.BlockDomain(domain); err != nil {
				log.WithError(err).Warnf("failed to block domain %s", domain)
			}
		}
		log.Infof("Domains %s blocked", *domains)
	}

	// Set DNS mode
	mode := 0 // DROP
	if *dnsMode == "poison" {
		mode = 1
	}
	if err := xdpFilter.SetDNSMode(mode); err != nil {
		log.WithError(err).Warn("failed to set DNS mode")
	}
	log.Infof("DNS mode: %s", *dnsMode)

	if *domains != "" {
		log.Info("Traffic filter active (ports + domains). Press Ctrl+C to stop.")
	} else {
		log.Info("Traffic filter active (ports only). Press Ctrl+C to stop.")
	}

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
