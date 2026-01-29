package natpmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// PortMappingResponse represents a parsed NAT-PMP port mapping response
type PortMappingResponse struct {
	ResultCode   uint16
	Epoch        uint32
	InternalPort uint16
	ExternalPort uint16
	Lifetime     uint32
}

// CreatePortMappingRequest creates a NAT-PMP port mapping request
func createPortMappingRequest(protocol string, internalPort, externalPort uint16, lifetime uint32) []byte {
	request := make([]byte, 12)
	request[0] = VersionNATPMP // Version 0
	if protocol == "tcp" {
		request[1] = OpcodeMapTCP
	} else {
		request[1] = OpcodeMapUDP
	}
	// Bytes 2-3: Reserved (zero)
	binary.BigEndian.PutUint16(request[4:6], internalPort)
	binary.BigEndian.PutUint16(request[6:8], externalPort)
	binary.BigEndian.PutUint32(request[8:12], lifetime)
	return request
}

// parsePortMappingResponse parses a NAT-PMP port mapping response
func parsePortMappingResponse(data []byte) (*PortMappingResponse, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	response := &PortMappingResponse{
		ResultCode:   binary.BigEndian.Uint16(data[2:4]),
		Epoch:        binary.BigEndian.Uint32(data[4:8]),
		InternalPort: binary.BigEndian.Uint16(data[8:10]),
		ExternalPort: binary.BigEndian.Uint16(data[10:12]),
		Lifetime:     binary.BigEndian.Uint32(data[12:16]),
	}

	if response.ResultCode != ResultSuccess {
		return response, fmt.Errorf("NAT-PMP error: result code %d", response.ResultCode)
	}

	return response, nil
}

// forwardRequest forwards a request to a NAT-PMP gateway and returns the response
func forwardRequest(data []byte, gateway net.IP, timeout time.Duration) ([]byte, error) {
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

// Client wraps the NAT-PMP client with retry and timeout logic
type Client struct {
	gateway net.IP
}

// NewClient creates a new NAT-PMP client
func NewClient(gateway net.IP) *Client {
	return &Client{
		gateway: gateway,
	}
}

// AddPortMapping creates a port mapping with retry and timeout
func (c *Client) AddPortMapping(protocol string, internalPort, externalPort, lifetime int) (*PortMappingResponse, error) {
	request := createPortMappingRequest(protocol, uint16(internalPort), uint16(externalPort), uint32(lifetime))

	// Forward with retry
	var responseData []byte
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		responseData, err = forwardRequest(request, c.gateway, 10*time.Second)
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Second)
		}
	}

	if err != nil {
		return nil, err
	}

	return parsePortMappingResponse(responseData)
}

// DeletePortMapping removes a port mapping (sets lifetime to 0)
func (c *Client) DeletePortMapping(protocol string, internalPort int) error {
	request := createPortMappingRequest(protocol, uint16(internalPort), 0, 0)
	_, err := forwardRequest(request, c.gateway, 10*time.Second)
	return err
}
