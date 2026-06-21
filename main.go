package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("parse args: %v", err)
	}

	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	if os.Geteuid() != 0 {
		log.Fatal("must run as root")
	}

	log.WithFields(log.Fields{
		"iface":    cfg.Iface,
		"domains":  len(cfg.Domains),
		"ips":      len(cfg.IPs),
		"ip_ports": len(cfg.IPPorts),
		"dns_mode": cfg.DNSMode,
	}).Info("starting traffic filter")

	capFD, _, err := openSockets(cfg.Iface)
	if err != nil {
		log.Fatalf("open sockets: %v", err)
	}
	defer unix.Close(capFD)
	defer unix.Close(injectSock)

	eng := newFilterEngine(cfg)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var total, blocked, rstCnt, dnsCnt uint64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	buf := make([]byte, maxBufSz)

	log.Info("filter running — Ctrl+C to stop")

loop:
	for {
		select {
		case <-sig:
			break loop
		case <-ticker.C:
			sec := uint64(5)
			log.WithFields(log.Fields{
				"total":  total,
				"blocked": blocked,
				"rst":    rstCnt,
				"dns":    dnsCnt,
				"total/s":  total / sec,
				"blocked/s": blocked / sec,
			}).Info("stats")
		default:
			n, _, err := unix.Recvfrom(capFD, buf, 0)
			if err != nil {
				continue
			}
			total++

			if n < ethHdrLen+ipHdrLen {
				continue
			}

			// Only IPv4
			if u16(buf[12:14]) != 0x0800 {
				continue
			}

			var ip [20]byte
			copy(ip[:], buf[14:34])

			v := eng.evaluate(buf, n)

			switch v.action {
			case "pass":
			case "drop":
				blocked++
			case "rst":
				blocked++
				rstCnt++
				sendTCPRST(buf, ip, v.tcpOff)
				log.WithField("rst", "sent").Debug("TCP RST injected")
			case "dns-poison":
				blocked++
				dnsCnt++
				sendDNSPoison(buf, ip, v.udpOff, v.dnsOff)
				log.WithField("poison", "sent").Debug("DNS poison injected")
			}
		}
	}

	log.Info("shutting down...")
}
