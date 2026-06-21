package main

import (
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// Stats holds packet statistics
type Stats struct {
	TotalPackets   uint64
	BlockedPackets uint64
	lastTotal      uint64
	lastBlocked    uint64
}

// NewStats creates a new stats tracker
func NewStats() *Stats {
	return &Stats{}
}

// StartPrinter prints stats at regular intervals
func (s *Stats) StartPrinter(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			s.PrintDelta()
		}
	}()
}

// PrintDelta prints stats since last call
func (s *Stats) PrintDelta() {
	total := atomic.LoadUint64(&s.TotalPackets)
	blocked := atomic.LoadUint64(&s.BlockedPackets)

	deltaTot := total - s.lastTotal
	deltaBlk := blocked - s.lastBlocked

	log.WithFields(log.Fields{
		"total":     total,
		"blocked":   blocked,
		"total/s":   deltaTot / 5, // Assuming 5 second interval
		"blocked/s": deltaBlk / 5,
	}).Info("stats")

	s.lastTotal = total
	s.lastBlocked = blocked
}

// Print prints final stats
func (s *Stats) Print() {
	total := atomic.LoadUint64(&s.TotalPackets)
	blocked := atomic.LoadUint64(&s.BlockedPackets)

	log.WithFields(log.Fields{
		"total_packets":   total,
		"blocked_packets": blocked,
		"pass_packets":    total - blocked,
	}).Info("final statistics")
}
