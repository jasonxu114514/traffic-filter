package main

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// NFTablesManager manages nftables rules for NFQUEUE
type NFTablesManager struct {
	mode     string // "local", "gateway", or "all"
	queueNum uint16 // NFQUEUE queue number
	rules    []string // Stored rules for cleanup
}

// NewNFTablesManager creates a new nftables manager
func NewNFTablesManager(mode string, queueNum uint16) *NFTablesManager {
	return &NFTablesManager{
		mode:     mode,
		queueNum: queueNum,
		rules:    make([]string, 0),
	}
}

// Setup adds nftables rules based on mode
func (m *NFTablesManager) Setup() error {
	// Create table
	cmd := exec.Command("nft", "add", "table", "inet", "traffic_filter")
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "File exists") && !strings.Contains(string(output), "exists") {
			return fmt.Errorf("failed to create table: %w, output: %s", err, string(output))
		}
	}

	chains := m.getChains()

	for _, chain := range chains {
		// Create chain - use separate command for hook definition
		chainName := fmt.Sprintf("tf_%s", chain)
		hookType := fmt.Sprintf("{ type filter hook %s priority 0 ; policy accept ; }", chain)

		cmd := exec.Command("nft", "add", "chain", "inet", "traffic_filter", chainName, hookType)
		if output, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "File exists") && !strings.Contains(string(output), "exists") {
				log.WithError(err).WithField("output", string(output)).Warn("chain creation failed")
			}
		}

		// HTTP (port 80)
		if err := m.addRule(chainName, "tcp", "80"); err != nil {
			return fmt.Errorf("failed to add HTTP rule: %w", err)
		}

		// HTTPS (port 443)
		if err := m.addRule(chainName, "tcp", "443"); err != nil {
			return fmt.Errorf("failed to add HTTPS rule: %w", err)
		}

		// DNS (port 53)
		if err := m.addRule(chainName, "udp", "53"); err != nil {
			return fmt.Errorf("failed to add DNS rule: %w", err)
		}
	}

	log.WithFields(log.Fields{
		"mode":   m.mode,
		"chains": chains,
		"queue":  m.queueNum,
	}).Info("nftables rules added")

	return nil
}

// Cleanup removes all added nftables rules
func (m *NFTablesManager) Cleanup() error {
	// Simply delete the entire table
	cmd := exec.Command("nft", "delete", "table", "inet", "traffic_filter")
	if err := cmd.Run(); err != nil {
		log.WithError(err).Warn("failed to delete nftables table")
	}

	log.Info("nftables rules removed")
	return nil
}

// addRule adds a single nftables rule
func (m *NFTablesManager) addRule(chain, proto, port string) error {
	// nft add rule inet traffic_filter tf_output tcp dport 80 queue to 0
	rule := fmt.Sprintf("add rule inet traffic_filter %s %s dport %s queue to %d",
		chain, proto, port, m.queueNum)

	parts := strings.Fields(rule)
	cmd := exec.Command("nft", parts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft command failed: %w, output: %s", err, string(output))
	}

	// Store the rule for later cleanup
	m.rules = append(m.rules, rule)

	log.WithFields(log.Fields{
		"chain": chain,
		"proto": proto,
		"port":  port,
	}).Debug("nftables rule added")

	return nil
}

// getChains returns the chains to use based on mode
func (m *NFTablesManager) getChains() []string {
	switch m.mode {
	case "local":
		return []string{"output"}
	case "gateway":
		return []string{"forward"}
	case "all":
		return []string{"output", "forward"}
	default:
		log.WithField("mode", m.mode).Warn("unknown mode, defaulting to local")
		return []string{"output"}
	}
}
