package mikrotik

import (
	"context"
	"fmt"
	gslog "log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/go-routeros/routeros/v3"
)

var slog = gslog.Default().With("component", "natpmp-client")

// Client wraps the MikroTik RouterOS API client
type Client struct {
	client *routeros.Client
	config *config.Config
	mu     sync.Mutex // Protects concurrent API calls
}

// PortMappingResult represents the result of creating a port mapping
type PortMappingResult struct {
	RuleID       string
	ExternalPort uint16
	Lifetime     uint32
}

// NewClient creates a new MikroTik API client
func NewClient(cfg *config.Config) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var client *routeros.Client
	var err error

	if cfg.LocalAPIUseTLS {
		client, err = routeros.DialTLSContext(ctx, cfg.LocalAPIAddress, cfg.LocalAPIUser, cfg.LocalAPIPassword, nil)
	} else {
		client, err = routeros.DialContext(ctx, cfg.LocalAPIAddress, cfg.LocalAPIUser, cfg.LocalAPIPassword)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to MikroTik API: %w", err)
	}

	slog.Info("Connected to MikroTik API", "address", cfg.LocalAPIAddress, "tls", cfg.LocalAPIUseTLS)

	return &Client{
		client: client,
		config: cfg,
	}, nil
}

// Close closes the MikroTik API connection
func (c *Client) Close() error {
	if c.client != nil {
		c.client.Close()
	}
	return nil
}

// GetInterfaceForGateway determines which interface would be used to reach the gateway
func (c *Client) GetInterfaceForGateway(gateway string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Use /ip/route/check to determine the actual route that would be used
	reply, err := c.client.Run(
		"/ip/route/check",
		"=dst-address="+gateway,
	)

	if err != nil {
		return "", fmt.Errorf("failed to check route: %w", err)
	}

	if len(reply.Re) == 0 {
		return "", fmt.Errorf("no route found for gateway %s", gateway)
	}

	// The interface field tells us which interface would be used
	iface := reply.Re[0].Map["interface"]
	if iface == "" {
		return "", fmt.Errorf("no interface found in route check for gateway %s", gateway)
	}

	return iface, nil
}

// isPortAvailable checks if a dst-port is already in use by any dst-nat rule
func (c *Client) isPortAvailable(protocol string, port int) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.isPortAvailableLocked(protocol, port)
}

// isPortAvailableLocked is the internal version that assumes mutex is already held
func (c *Client) isPortAvailableLocked(protocol string, port int) (bool, error) {
	protocolLower := protocol
	if protocol == "tcp" || protocol == "TCP" {
		protocolLower = "tcp"
	} else {
		protocolLower = "udp"
	}

	portStr := fmt.Sprintf("%d", port)

	// Query all dst-nat rules matching this protocol and port on our interface
	reply, err := c.client.Run(
		"/ip/firewall/nat/print",
		"?chain=dstnat",
		"?protocol="+protocolLower,
		"?dst-port="+portStr,
		"?in-interface="+c.config.LocalInInterface,
	)

	if err != nil {
		return false, fmt.Errorf("failed to query existing rules: %w", err)
	}

	// Port is available if no rules were found
	return len(reply.Re) == 0, nil
}

// getUsedPorts fetches all dst-nat ports currently in use on the interface for a given protocol
func (c *Client) getUsedPorts(protocol string) (map[int]bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	protocolLower := protocol
	if protocol == "tcp" || protocol == "TCP" {
		protocolLower = "tcp"
	} else {
		protocolLower = "udp"
	}

	// Query all dst-nat rules for this protocol on our interface
	reply, err := c.client.Run(
		"/ip/firewall/nat/print",
		"?chain=dstnat",
		"?protocol="+protocolLower,
		"?in-interface="+c.config.LocalInInterface,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query existing rules: %w", err)
	}

	usedPorts := make(map[int]bool)
	for _, re := range reply.Re {
		portStr := re.Map["dst-port"]
		if portStr == "" {
			continue
		}

		// Handle port ranges like "8080-8090" by marking all ports in range as used
		// and simple ports like "8080"
		if strings.Contains(portStr, "-") {
			// Port range
			parts := strings.Split(portStr, "-")
			if len(parts) == 2 {
				startPort, err1 := strconv.Atoi(parts[0])
				endPort, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil {
					for p := startPort; p <= endPort; p++ {
						usedPorts[p] = true
					}
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(portStr)
			if err == nil {
				usedPorts[port] = true
			}
		}
	}

	return usedPorts, nil
}

// FindAvailablePort finds an available port starting from the suggested port
// It fetches all used ports once and searches locally for efficiency
func (c *Client) FindAvailablePort(protocol string, suggestedPort int) (int, error) {
	const maxAttempts = 1000
	const maxPort = 65535

	// Fetch all used ports once
	usedPorts, err := c.getUsedPorts(protocol)
	if err != nil {
		return 0, fmt.Errorf("failed to get used ports: %w", err)
	}

	slog.Debug("Port availability check", "protocol", protocol, "used_ports_count", len(usedPorts))

	// Start from suggested port, or from 49152 (dynamic port range) if 0
	startPort := suggestedPort
	if startPort == 0 {
		startPort = 49152
	}

	// Search for available port
	for i := 0; i < maxAttempts; i++ {
		port := startPort + i
		if port > maxPort {
			// Wrap around to dynamic port range
			port = 49152 + (port - maxPort - 1)
		}

		if !usedPorts[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports found after %d attempts starting from port %d", maxAttempts, startPort)
}

// AddPortMapping creates a dst-nat rule for port forwarding with retry
func (c *Client) AddPortMapping(protocol string, internalPort, externalPort int, lifetime uint32, toAddress string) (*PortMappingResult, error) {
	// First attempt
	result, err := c.addPortMapping(protocol, internalPort, externalPort, lifetime, toAddress)
	if err != nil {
		// Retry once after 1 second
		time.Sleep(1 * time.Second)
		result, err = c.addPortMapping(protocol, internalPort, externalPort, lifetime, toAddress)
	}
	return result, err
}

// addPortMapping is the internal implementation without retry
func (c *Client) addPortMapping(protocol string, internalPort, externalPort int, lifetime uint32, toAddress string) (*PortMappingResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	protocolLower := protocol
	if protocol == "tcp" || protocol == "TCP" {
		protocolLower = "tcp"
	} else {
		protocolLower = "udp"
	}

	portStr := fmt.Sprintf("%d", externalPort)
	if externalPort == 0 {
		portStr = fmt.Sprintf("%d", internalPort)
	}

	// Check if port is available before attempting to create the rule
	requestedPort := externalPort
	if requestedPort == 0 {
		requestedPort = internalPort
	}

	available, err := c.isPortAvailableLocked(protocolLower, requestedPort)
	if err != nil {
		return nil, fmt.Errorf("failed to check port availability: %w", err)
	}

	if !available {
		return nil, fmt.Errorf("port %d/%s is already in use on interface %s", requestedPort, protocolLower, c.config.LocalInInterface)
	}

	comment := fmt.Sprintf("double-natpmp-%s-%d-%s", protocolLower, internalPort, toAddress)

	slog.Debug("Adding MikroTik dst-nat rule",
		"protocol", protocolLower,
		"in-interface", c.config.LocalInInterface,
		"dst-port", portStr,
		"to-addresses", toAddress,
		"to-ports", internalPort)

	reply, err := c.client.Run(
		"/ip/firewall/nat/add",
		"=chain=dstnat",
		"=action=dst-nat",
		"=protocol="+protocolLower,
		"=in-interface="+c.config.LocalInInterface,
		"=dst-port="+portStr,
		"=to-addresses="+toAddress,
		"=to-ports="+fmt.Sprintf("%d", internalPort),
		"=comment="+comment,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to add dst-nat rule: %w", err)
	}

	ruleID := reply.Done.Map["ret"]

	result := &PortMappingResult{
		RuleID:       ruleID,
		ExternalPort: uint16(externalPort),
		Lifetime:     lifetime,
	}

	if externalPort == 0 {
		result.ExternalPort = uint16(internalPort)
	}

	slog.Info("MikroTik dst-nat rule created", "rule_id", ruleID, "external_port", result.ExternalPort)

	return result, nil
}

// DeletePortMapping removes a dst-nat rule by finding it via comment
func (c *Client) DeletePortMapping(protocol string, internalPort int, toAddress string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protocolLower := protocol
	if protocol == "tcp" || protocol == "TCP" {
		protocolLower = "tcp"
	} else {
		protocolLower = "udp"
	}

	comment := fmt.Sprintf("double-natpmp-%s-%d-%s", protocolLower, internalPort, toAddress)

	// Find the rule by comment
	reply, err := c.client.Run(
		"/ip/firewall/nat/print",
		"?comment="+comment,
	)

	if err != nil {
		return fmt.Errorf("failed to find dst-nat rule: %w", err)
	}

	if len(reply.Re) == 0 {
		slog.Warn("MikroTik dst-nat rule not found for deletion", "comment", comment)
		return nil
	}

	ruleID := reply.Re[0].Map[".id"]

	// Delete the rule
	_, err = c.client.Run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule: %w", err)
	}

	slog.Info("MikroTik dst-nat rule deleted", "rule_id", ruleID)

	return nil
}

// DeletePortMappingByID removes a dst-nat rule by rule ID
func (c *Client) DeletePortMappingByID(ruleID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.client.Run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule: %w", err)
	}

	slog.Info("MikroTik dst-nat rule deleted", "rule_id", ruleID)

	return nil
}

// GetExternalIP returns the WAN IP address from the router
func (c *Client) GetExternalIP() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get the first active address from the WAN interface
	// This is router-specific - adjust based on your setup
	reply, err := c.client.Run("/ip/address/print")

	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %w", err)
	}

	if len(reply.Re) > 0 {
		// Return the first address found
		// You may need to filter by interface name
		address := reply.Re[0].Map["address"]
		return address, nil
	}

	return "", fmt.Errorf("no IP addresses found on router")
}

// NATRule represents a dst-nat rule from MikroTik
type NATRule struct {
	ID          string
	Protocol    string
	DstPort     string
	ToAddress   string
	ToPort      string
	Comment     string
	InInterface string
}

// GetAllDoubleNATPMPRules returns all dst-nat rules created by this service
func (c *Client) GetAllDoubleNATPMPRules() ([]NATRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find all rules with our comment prefix
	reply, err := c.client.Run(
		"/ip/firewall/nat/print",
		"?chain=dstnat",
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query dst-nat rules: %w", err)
	}

	rules := make([]NATRule, 0)

	for _, re := range reply.Re {
		comment := re.Map["comment"]
		// Check if this is one of our rules (starts with "double-natpmp-")
		if len(comment) > 14 && comment[:14] == "double-natpmp-" {
			rules = append(rules, NATRule{
				ID:          re.Map[".id"],
				Protocol:    re.Map["protocol"],
				DstPort:     re.Map["dst-port"],
				ToAddress:   re.Map["to-addresses"],
				ToPort:      re.Map["to-ports"],
				Comment:     comment,
				InInterface: re.Map["in-interface"],
			})
		}
	}

	slog.Info("Found existing double-natpmp rules", "count", len(rules))

	return rules, nil
}

// DeleteRuleByID removes a dst-nat rule by its ID
func (c *Client) DeleteRuleByID(ruleID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.client.Run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule %s: %w", ruleID, err)
	}

	slog.Info("Removed stale MikroTik rule", "rule_id", ruleID)

	return nil
}
