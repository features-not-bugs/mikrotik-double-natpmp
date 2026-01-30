package mikrotik

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/utility"
	"github.com/go-routeros/routeros/v3"
)

var slog = utility.GetLogger().With("component", "mikrotik-client")

const (
	defaultPoolSize   = 4
	connectionTimeout = 10 * time.Second
)

// pooledConn wraps a routeros.Client with health tracking
type pooledConn struct {
	client    *routeros.Client
	lastError time.Time
}

// Client wraps the MikroTik RouterOS API client with connection pooling
type Client struct {
	config *config.Config
	pool   chan *pooledConn
}

// PortMappingResult represents the result of creating a port mapping
type PortMappingResult struct {
	RuleID       string
	ExternalPort uint16
	Lifetime     uint32
}

// NewClient creates a new MikroTik API client with connection pooling
func NewClient(cfg *config.Config) (*Client, error) {
	c := &Client{
		config: cfg,
		pool:   make(chan *pooledConn, defaultPoolSize),
	}

	// Create initial connections
	for i := 0; i < defaultPoolSize; i++ {
		conn, err := c.dial()
		if err != nil {
			// Close any connections we've already made
			c.Close()
			return nil, fmt.Errorf("failed to create connection pool: %w", err)
		}
		c.pool <- conn
	}

	slog.Info("Connected to MikroTik API",
		"address", cfg.LocalAPIAddress,
		"tls", cfg.LocalAPIUseTLS,
		"pool_size", defaultPoolSize)

	return c, nil
}

// dial creates a new connection to the MikroTik router
func (c *Client) dial() (*pooledConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	var client *routeros.Client
	var err error

	if c.config.LocalAPIUseTLS {
		client, err = routeros.DialTLSContext(ctx, c.config.LocalAPIAddress, c.config.LocalAPIUser, c.config.LocalAPIPassword, nil)
	} else {
		client, err = routeros.DialContext(ctx, c.config.LocalAPIAddress, c.config.LocalAPIUser, c.config.LocalAPIPassword)
	}

	if err != nil {
		return nil, err
	}

	return &pooledConn{client: client}, nil
}

// acquire gets a connection from the pool
func (c *Client) acquire() *pooledConn {
	return <-c.pool
}

// release returns a connection to the pool, reconnecting if needed
func (c *Client) release(conn *pooledConn, err error) {
	if err != nil {
		// Connection may be bad, try to reconnect
		conn.client.Close()

		newConn, dialErr := c.dial()
		if dialErr != nil {
			slog.Warn("Failed to reconnect to MikroTik, will retry on next use", "error", dialErr)
			// Put a marker back so pool doesn't shrink
			conn.client = nil
			conn.lastError = time.Now()
			c.pool <- conn
			return
		}
		conn = newConn
	}
	c.pool <- conn
}

// run executes an API command with automatic connection management
func (c *Client) run(args ...string) (*routeros.Reply, error) {
	conn := c.acquire()

	// Check if this connection needs reconnection (from previous error)
	if conn.client == nil {
		// Try to reconnect
		newConn, err := c.dial()
		if err != nil {
			c.pool <- conn // Return the bad conn marker
			return nil, fmt.Errorf("connection unavailable: %w", err)
		}
		conn = newConn
	}

	reply, err := conn.client.Run(args...)
	c.release(conn, err)
	return reply, err
}

// Close closes all connections in the pool
func (c *Client) Close() error {
	close(c.pool)
	for conn := range c.pool {
		if conn.client != nil {
			conn.client.Close()
		}
	}
	return nil
}

// GetInterfaceForGateway determines which interface would be used to reach the gateway
func (c *Client) GetInterfaceForGateway(gateway string) (string, error) {
	reply, err := c.run(
		"/ip/route/check",
		"=dst-ip="+gateway,
		"=once",
	)

	if err != nil {
		return "", fmt.Errorf("failed to check route: %w", err)
	}

	if len(reply.Re) == 0 {
		return "", fmt.Errorf("no route found for gateway %s", gateway)
	}

	iface := reply.Re[0].Map["interface"]
	if iface == "" {
		return "", fmt.Errorf("no interface found in route check for gateway %s", gateway)
	}

	return iface, nil
}

// isPortAvailable checks if a dst-port is already in use by any dst-nat rule
func (c *Client) isPortAvailable(protocol string, port int) (bool, error) {
	protocolLower := normalizeProtocol(protocol)
	portStr := fmt.Sprintf("%d", port)

	reply, err := c.run(
		"/ip/firewall/nat/print",
		"?chain=dstnat",
		"?protocol="+protocolLower,
		"?dst-port="+portStr,
		"?in-interface="+c.config.LocalInInterface,
	)

	if err != nil {
		return false, fmt.Errorf("failed to query existing rules: %w", err)
	}

	return len(reply.Re) == 0, nil
}

// getUsedPorts fetches all dst-nat ports currently in use on the interface for a given protocol
func (c *Client) getUsedPorts(protocol string) (map[int]bool, error) {
	protocolLower := normalizeProtocol(protocol)

	reply, err := c.run(
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

		if strings.Contains(portStr, "-") {
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
			port, err := strconv.Atoi(portStr)
			if err == nil {
				usedPorts[port] = true
			}
		}
	}

	return usedPorts, nil
}

// FindAvailablePort finds an available port starting from the suggested port
func (c *Client) FindAvailablePort(protocol string, suggestedPort int) (int, error) {
	const maxAttempts = 1000
	const maxPort = 65535

	usedPorts, err := c.getUsedPorts(protocol)
	if err != nil {
		return 0, fmt.Errorf("failed to get used ports: %w", err)
	}

	slog.Debug("Port availability check", "protocol", protocol, "used_ports_count", len(usedPorts))

	startPort := suggestedPort
	if startPort == 0 {
		startPort = 49152
	}

	for i := 0; i < maxAttempts; i++ {
		port := startPort + i
		if port > maxPort {
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
	result, err := c.addPortMapping(protocol, internalPort, externalPort, lifetime, toAddress)
	if err != nil {
		time.Sleep(1 * time.Second)
		result, err = c.addPortMapping(protocol, internalPort, externalPort, lifetime, toAddress)
	}
	return result, err
}

// addPortMapping is the internal implementation without retry
func (c *Client) addPortMapping(protocol string, internalPort, externalPort int, lifetime uint32, toAddress string) (*PortMappingResult, error) {
	protocolLower := normalizeProtocol(protocol)

	portStr := fmt.Sprintf("%d", externalPort)
	if externalPort == 0 {
		portStr = fmt.Sprintf("%d", internalPort)
	}

	requestedPort := externalPort
	if requestedPort == 0 {
		requestedPort = internalPort
	}

	available, err := c.isPortAvailable(protocolLower, requestedPort)
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

	reply, err := c.run(
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

	slog.Debug("MikroTik dst-nat rule created", "rule_id", ruleID, "external_port", result.ExternalPort)

	return result, nil
}

// DeletePortMapping removes a dst-nat rule by finding it via comment
func (c *Client) DeletePortMapping(protocol string, internalPort int, toAddress string) error {
	protocolLower := normalizeProtocol(protocol)
	comment := fmt.Sprintf("double-natpmp-%s-%d-%s", protocolLower, internalPort, toAddress)

	reply, err := c.run(
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

	_, err = c.run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule: %w", err)
	}

	slog.Debug("MikroTik dst-nat rule deleted", "rule_id", ruleID)

	return nil
}

// DeletePortMappingByID removes a dst-nat rule by rule ID
func (c *Client) DeletePortMappingByID(ruleID string) error {
	_, err := c.run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule: %w", err)
	}

	slog.Debug("MikroTik dst-nat rule deleted", "rule_id", ruleID)

	return nil
}

// GetExternalIP returns the WAN IP address from the router
func (c *Client) GetExternalIP() (string, error) {
	reply, err := c.run("/ip/address/print")

	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %w", err)
	}

	if len(reply.Re) > 0 {
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
	reply, err := c.run(
		"/ip/firewall/nat/print",
		"?chain=dstnat",
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query dst-nat rules: %w", err)
	}

	rules := make([]NATRule, 0)

	for _, re := range reply.Re {
		comment := re.Map["comment"]
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

	slog.Debug("Found existing double-natpmp rules", "count", len(rules))

	return rules, nil
}

// DeleteRuleByID removes a dst-nat rule by its ID
func (c *Client) DeleteRuleByID(ruleID string) error {
	_, err := c.run(
		"/ip/firewall/nat/remove",
		"=.id="+ruleID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete dst-nat rule %s: %w", ruleID, err)
	}

	slog.Info("Removed stale MikroTik rule", "rule_id", ruleID)

	return nil
}

// normalizeProtocol converts protocol string to lowercase
func normalizeProtocol(protocol string) string {
	if protocol == "tcp" || protocol == "TCP" {
		return "tcp"
	}
	return "udp"
}
