package natpmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Protocol constants
const (
	OpcodePublicAddress = 0
	OpcodeMapUDP        = 1
	OpcodeMapTCP        = 2

	VersionNATPMP = 0
	VersionPCP    = 2

	ResultSuccess        = 0
	ResultUnsuppVersion  = 1
	ResultNotAuthorized  = 2
	ResultNetworkFailure = 3
	ResultOutOfResources = 4
	ResultUnsuppOpcode   = 5
)

// Request represents a parsed NAT-PMP request
type Request struct {
	Version          byte
	Opcode           byte
	InternalPort     uint16
	SuggestedExtPort uint16
	Lifetime         uint32
}

// ParseRequest parses a NAT-PMP request packet
func ParseRequest(data []byte) (*Request, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("request too short")
	}

	req := &Request{
		Version: data[0],
		Opcode:  data[1],
	}

	// Parse port mapping fields if applicable
	if (req.Opcode == OpcodeMapUDP || req.Opcode == OpcodeMapTCP) && len(data) >= 12 {
		req.InternalPort = binary.BigEndian.Uint16(data[4:6])
		req.SuggestedExtPort = binary.BigEndian.Uint16(data[6:8])
		req.Lifetime = binary.BigEndian.Uint32(data[8:12])
	}

	return req, nil
}

// ForwardRequest forwards a request to a NAT-PMP gateway and returns the response
// This is used by both server (for PUBLIC_ADDRESS forwarding) and client
func ForwardRequest(data []byte, gateway net.IP, timeout time.Duration) ([]byte, error) {
	gatewayAddr := &net.UDPAddr{
		IP:   gateway,
		Port: 5351,
	}

	conn, err := net.DialUDP("udp4", nil, gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gateway: %w", err)
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// Send request
	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buffer[:n], nil
}
