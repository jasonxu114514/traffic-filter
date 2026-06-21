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
	// Create table if not exists
	cmd := exec.Command("nft", "add", "table", "inet", "filter")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore if table already exists
		if !strings.Contains(string(output), "File exists") {
			log.WithError(err).WithField("output", string(output)).Debug("table creation info")
		}
	}

	chains := m.getChains()

	for _, chain := range chains {
		// Create chain if not exists
		chainName := strings.ToLower(chain)
		cmd := exec.Command("nft", "add", "chain", "inet", "filter", chainName,
			fmt.Sprintf("{ type filter hook %s priority 0 ; }", chainName))
		if output, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "File exists") {
				log.WithError(err).WithField("output", string(output)).Debug("chain creation info")
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
	// Remove rules in reverse order
	for i := len(m.rules) - 1; i >= 0; i-- {
		rule := m.rules[i]
		parts := strings.Fields(rule)

		// Change "add rule" to "delete rule"
		if len(parts) >= 2 && parts[0] == "add" {
			parts[0] = "delete"
		}

		cmd := exec.Command("nft", parts...)
		if err := cmd.Run(); err != nil {
			log.WithError(err).WithField("rule", rule).Warn("failed to remove nftables rule")
		}
	}

	log.WithField("count", len(m.rules)).Info("nftables rules removed")
	return nil
}

// addRule adds a single nftables rule
func (m *NFTablesManager) addRule(chain, proto, port string) error {
	// nft add rule inet filter output tcp dport 80 queue num 0
	rule := fmt.Sprintf("add rule inet filter %s %s dport %s queue num %d",
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
