package config

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// Config holds the application configuration
type Config struct {
	LocalAPIAddress  string // MikroTik API address (IP:port)
	LocalAPIUser     string
	LocalAPIPassword string
	LocalAPIUseTLS   bool
	LocalInInterface string // MikroTik interface for dst-nat rules (e.g., "bridge")
	VpnGateway       net.IP
	ListenAddr       string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	vpnGatewayStr := os.Getenv("VPN_GATEWAY")
	if vpnGatewayStr == "" {
		return nil, errors.New("VPN_GATEWAY environment variable is required")
	}

	vpnGateway := net.ParseIP(vpnGatewayStr)
	if vpnGateway == nil {
		return nil, fmt.Errorf("invalid VPN_GATEWAY IP address: %s", vpnGatewayStr)
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":5351"
	}

	// MikroTik API configuration
	localAPIAddress := os.Getenv("MIKROTIK_API_ADDRESS")
	if localAPIAddress == "" {
		return nil, errors.New("MIKROTIK_API_ADDRESS environment variable is required")
	}

	localAPIUser := os.Getenv("MIKROTIK_API_USER")
	if localAPIUser == "" {
		localAPIUser = "admin"
	}

	localAPIPassword := os.Getenv("MIKROTIK_API_PASSWORD")
	if localAPIPassword == "" {
		return nil, errors.New("MIKROTIK_API_PASSWORD environment variable is required")
	}

	localAPIUseTLS := os.Getenv("MIKROTIK_API_TLS") == "true"

	localInInterface := os.Getenv("MIKROTIK_IN_INTERFACE")
	if localInInterface == "" {
		localInInterface = "" // Will be auto-detected if empty
	}

	return &Config{
		LocalAPIAddress:  localAPIAddress,
		LocalAPIUser:     localAPIUser,
		LocalAPIPassword: localAPIPassword,
		LocalAPIUseTLS:   localAPIUseTLS,
		LocalInInterface: localInInterface,
		VpnGateway:       vpnGateway,
		ListenAddr:       listenAddr,
	}, nil
}
