package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/traffic-filter/pkg/config"
	"github.com/traffic-filter/pkg/filter"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	if os.Geteuid() != 0 {
		log.Fatal("this program requires root privileges")
	}

	log.WithFields(log.Fields{
		"interface":    cfg.Interface,
		"domains":      len(cfg.Domains),
		"ips":          len(cfg.IPs),
		"ip_ports":     len(cfg.IPPorts),
		"dns_mode":     cfg.DNSMode,
		"ip_mode":      cfg.IPMode,
		"ip_port_mode": cfg.IPPortMode,
	}).Info("starting traffic filter")

	tf, err := filter.New(cfg)
	if err != nil {
		log.Fatalf("create filter: %v", err)
	}
	defer tf.Close()

	stop := make(chan struct{})
	go tf.RunStatsMonitor(5*time.Second, stop)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Info("filter running — press Ctrl+C to stop")
	<-sig

	close(stop)
	log.Info("shutting down...")
}
