package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {
	// CLI flags
	mode := flag.String("mode", "local", "Filter mode: local, gateway, all")
	domains := flag.String("domains", "", "Blocked domains (comma-separated)")
	blockIPs := flag.String("block-ips", "", "Blocked IPs (comma-separated)")
	queueNum := flag.Uint("queue", 0, "NFQUEUE queue number")
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

	// Check if nfnetlink_queue module is loaded
	checkNFQueueModule()

	// Initialize filter
	filter := NewFilter(*domains, *blockIPs)
	stats := NewStats()

	log.WithFields(log.Fields{
		"mode":    *mode,
		"domains": *domains,
		"ips":     *blockIPs,
		"queue":   *queueNum,
	}).Info("Traffic Filter starting (NFQUEUE mode)")

	// Setup nftables rules
	nftMgr := NewNFTablesManager(*mode, uint16(*queueNum))
	if err := nftMgr.Setup(); err != nil {
		log.WithError(err).Fatal("failed to setup nftables")
	}
	defer func() {
		log.Info("Cleaning up nftables rules...")
		nftMgr.Cleanup()
	}()

	// Create NFQUEUE handler
	handler, err := NewNFQueueHandler(uint16(*queueNum), filter, stats)
	if err != nil {
		log.WithError(err).Fatal("failed to create nfqueue handler")
	}
	defer handler.Close()

	// Start stats printer
	stats.StartPrinter(5 * time.Second)

	// Start NFQUEUE processing
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := handler.Start(ctx); err != nil {
			log.WithError(err).Error("nfqueue handler error")
		}
	}()

	log.Info("Filter active. Press Ctrl+C to stop.")

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")
	cancel()
	time.Sleep(time.Second)

	// Print final stats
	stats.Print()
}

// checkNFQueueModule checks and loads nfnetlink_queue module if needed
func checkNFQueueModule() {
	// Try to load the module
	cmd := exec.Command("modprobe", "nfnetlink_queue")
	if err := cmd.Run(); err != nil {
		log.WithError(err).Warn("failed to load nfnetlink_queue module (may already be loaded)")
	}
}
