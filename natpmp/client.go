package natpmp

import (
	"fmt"
	"net"
	"time"
)

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

// GetExternalAddress retrieves the external ip address of the gateway
func (c *Client) GetExternalAddress() (*ExternalAddressResponse, error) {
	request := make([]byte, 2)
	// Version
	request[0] = 0
	// OpCode
	request[1] = byte(opcodePublicAddress)

	responseData, err := c.sendReceive(request, 10*time.Second)
	if err != nil {
		return nil, err
	}

	if len(responseData) != 12 {
		return nil, fmt.Errorf("invalid response: %d bytes", len(responseData))
	}

	version := responseData[0]
	if version != 0 {
		return nil, fmt.Errorf("invalid version response: %d", version)
	}

	opCode := responseData[1]
	if opCode != byte(opcodePublicAddress)|0x80 {
		return nil, fmt.Errorf("invalid opcode in response: %d", opCode)
	}

	response := &ExternalAddressResponse{}
	err = response.fromBytes(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize response bytes: %w", err)
	}
	return response, nil
}

// SendPortMappingRequest sends a request to the gateway to map a port to us downstream
// Set the lifetime to 0 for an unmap request
// Set the internal and external port to 0 for all ports (you can also specify each individually)
func (c *Client) SendPortMappingRequest(request *PortMappingRequest) (*PortMappingResponse, error) {
	// Use shorter timeout for deletion requests (best effort cleanup)
	timeout := 10 * time.Second
	if request.RequestedLifetimeInSeconds == 0 {
		timeout = 2 * time.Second
	}

	responseData, err := c.sendReceive(request.toBytes(), timeout)
	if err != nil {
		return nil, err
	}

	if len(responseData) != 16 {
		return nil, fmt.Errorf("invalid response: %d bytes", len(responseData))
	}

	version := responseData[0]
	if version != 0 {
		return nil, fmt.Errorf("invalid version response: %d", version)
	}

	opCode := responseData[1]
	if opCode != byte(protocolOpcodeMap[request.Protocol])|0x80 {
		return nil, fmt.Errorf("invalid opcode response: %d", opCode)
	}

	response := &PortMappingResponse{}
	err = response.fromBytes(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize response bytes: %w", err)
	}

	if response.ResultCode != ResultSuccess {
		return response, fmt.Errorf("NAT-PMP error: result code %d", response.ResultCode)
	}

	return response, nil
}

// sendReceive sends and receives data to and from the gateway
func (c *Client) sendReceive(data []byte, timeout time.Duration) ([]byte, error) {
	gatewayAddr := &net.UDPAddr{
		IP:   c.gateway,
		Port: 5351,
	}

	conn, err := net.DialUDP("udp4", nil, gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gateway: %w", err)
	}
	defer conn.Close()

	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}

	// Send
	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1024) // TODO: this should probably be set the the MTU of the interface? idk
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buffer[:n], nil
}
