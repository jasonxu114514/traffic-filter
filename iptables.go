package main

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// IPTablesManager manages iptables rules for NFQUEUE
type IPTablesManager struct {
	mode     string   // "local", "gateway", or "all"
	queueNum uint16   // NFQUEUE queue number
	rules    [][]string // Stored rules for cleanup
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager(mode string, queueNum uint16) *IPTablesManager {
	return &IPTablesManager{
		mode:     mode,
		queueNum: queueNum,
		rules:    make([][]string, 0),
	}
}

// Setup adds iptables rules based on mode
func (m *IPTablesManager) Setup() error {
	chains := m.getChains()

	for _, chain := range chains {
		// HTTP (port 80)
		if err := m.addRule(chain, "tcp", "80"); err != nil {
			return fmt.Errorf("failed to add HTTP rule: %w", err)
		}

		// HTTPS (port 443)
		if err := m.addRule(chain, "tcp", "443"); err != nil {
			return fmt.Errorf("failed to add HTTPS rule: %w", err)
		}

		// DNS (port 53)
		if err := m.addRule(chain, "udp", "53"); err != nil {
			return fmt.Errorf("failed to add DNS rule: %w", err)
		}
	}

	log.WithFields(log.Fields{
		"mode":   m.mode,
		"chains": chains,
		"queue":  m.queueNum,
	}).Info("iptables rules added")

	return nil
}

// Cleanup removes all added iptables rules
func (m *IPTablesManager) Cleanup() error {
	// Remove in reverse order
	for i := len(m.rules) - 1; i >= 0; i-- {
		rule := m.rules[i]
		// Change -A (append) to -D (delete)
		rule[1] = "-D"

		cmd := exec.Command("iptables", rule...)
		if err := cmd.Run(); err != nil {
			log.WithError(err).WithField("rule", rule).Warn("failed to remove iptables rule")
			// Continue trying to remove other rules
		}
	}

	log.WithField("count", len(m.rules)).Info("iptables rules removed")
	return nil
}

// addRule adds a single iptables rule
func (m *IPTablesManager) addRule(chain, proto, port string) error {
	rule := []string{
		"-A", chain,
		"-p", proto,
		"--dport", port,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", m.queueNum),
	}

	cmd := exec.Command("iptables", rule...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables command failed: %w, output: %s", err, string(output))
	}

	// Store the rule for later cleanup
	m.rules = append(m.rules, rule)

	log.WithFields(log.Fields{
		"chain": chain,
		"proto": proto,
		"port":  port,
	}).Debug("iptables rule added")

	return nil
}

// getChains returns the chains to use based on mode
func (m *IPTablesManager) getChains() []string {
	switch m.mode {
	case "local":
		return []string{"OUTPUT"}
	case "gateway":
		return []string{"FORWARD"}
	case "all":
		return []string{"OUTPUT", "FORWARD"}
	default:
		log.WithField("mode", m.mode).Warn("unknown mode, defaulting to local")
		return []string{"OUTPUT"}
	}
}
