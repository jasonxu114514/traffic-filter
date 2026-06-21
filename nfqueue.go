package main

import (
	"context"
	"fmt"

	"github.com/florianl/go-nfqueue"
	log "github.com/sirupsen/logrus"
)

// NFQueueHandler handles packets from NFQUEUE
type NFQueueHandler struct {
	nf     *nfqueue.Nfqueue
	filter *Filter
	stats  *Stats
}

// NewNFQueueHandler creates a new NFQUEUE handler
func NewNFQueueHandler(queueNum uint16, filter *Filter, stats *Stats) (*NFQueueHandler, error) {
	config := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to open nfqueue: %w", err)
	}

	return &NFQueueHandler{
		nf:     nf,
		filter: filter,
		stats:  stats,
	}, nil
}

// Start begins processing packets from NFQUEUE
func (h *NFQueueHandler) Start(ctx context.Context) error {
	fn := func(a nfqueue.Attribute) int {
		h.stats.TotalPackets++

		// Check if packet has payload
		if a.Payload == nil || len(*a.Payload) == 0 {
			h.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			return 0
		}

		packet := *a.Payload

		// Check if packet should be blocked
		if h.filter.ShouldBlock(packet) {
			h.stats.BlockedPackets++
			h.nf.SetVerdict(*a.PacketID, nfqueue.NfDrop)

			log.WithFields(log.Fields{
				"action": "DROP",
				"size":   len(packet),
			}).Debug("packet blocked")
		} else {
			h.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}

		return 0
	}

	errFunc := func(e error) int {
		log.WithError(e).Error("nfqueue error")
		return 0
	}

	if err := h.nf.RegisterWithErrorFunc(ctx, fn, errFunc); err != nil {
		return fmt.Errorf("failed to register nfqueue callback: %w", err)
	}

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Close closes the NFQUEUE handle
func (h *NFQueueHandler) Close() error {
	if h.nf != nil {
		return h.nf.Close()
	}
	return nil
}
