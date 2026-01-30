package natpmp

import (
	"encoding/binary"
	"fmt"
	"net"
)

type opCode uint8
type Protocol uint8
type Result uint16

// Protocol constants
const (
	ProtocolUDP = Protocol(1)
	ProtocolTCP = Protocol(2)

	opcodePublicAddress = opCode(0)
	opcodeMapUDP        = opCode(1)
	opcodeMapTCP        = opCode(2)

	ResultSuccess            = Result(0)
	ResultUnsupportedVersion = Result(1)
	ResultNotAuthorized      = Result(2)
	ResultNetworkFailure     = Result(3)
	ResultOutOfResources     = Result(4)
	ResultUnsupportedOpcode  = Result(5)
)

var (
	protocolOpcodeMap = map[Protocol]opCode{
		ProtocolUDP: opcodeMapUDP,
		ProtocolTCP: opcodeMapTCP,
	}
	opCodeProtocolMap = map[opCode]Protocol{
		opcodeMapUDP: ProtocolUDP,
		opcodeMapTCP: ProtocolTCP,
	}
)

// PortMappingResponse represents a parsed NAT-PMP port mapping response
type PortMappingResponse struct {
	Protocol     Protocol
	ResultCode   Result
	Epoch        uint32
	InternalPort uint16
	ExternalPort uint16
	Lifetime     uint32
}

func (p *PortMappingResponse) toBytes() []byte {
	bytes := make([]byte, 16)
	// Version
	bytes[0] = 0
	// OpCode
	bytes[1] = byte(protocolOpcodeMap[p.Protocol]) | 0x80
	// ResultCode
	binary.BigEndian.PutUint16(bytes[2:4], uint16(p.ResultCode))
	// Epoch
	binary.BigEndian.PutUint32(bytes[4:8], p.Epoch)
	// Internal Port
	binary.BigEndian.PutUint16(bytes[8:10], p.InternalPort)
	// External Port
	binary.BigEndian.PutUint16(bytes[10:12], p.ExternalPort)
	// Lifetime
	binary.BigEndian.PutUint32(bytes[12:16], p.Lifetime)

	return bytes
}

func (p *PortMappingResponse) fromBytes(bytes []byte) error {
	if len(bytes) < 16 {
		return fmt.Errorf("invalid byte length of payload, was expecting 16, got %d", len(bytes))
	}
	p.ResultCode = Result(binary.BigEndian.Uint16(bytes[2:4]))
	p.Epoch = binary.BigEndian.Uint32(bytes[4:8])
	p.InternalPort = binary.BigEndian.Uint16(bytes[8:10])
	p.ExternalPort = binary.BigEndian.Uint16(bytes[10:12])
	p.Lifetime = binary.BigEndian.Uint32(bytes[12:16])
	return nil
}

// PortMappingRequest represents a parsed NAT-PMP port mapping request
type PortMappingRequest struct {
	Protocol                   Protocol
	InternalPort               uint16
	SuggestedExternalPort      uint16
	RequestedLifetimeInSeconds uint32
}

func (p *PortMappingRequest) toBytes() []byte {
	bytes := make([]byte, 12)
	// Version
	bytes[0] = 0
	// OpCode
	bytes[1] = byte(protocolOpcodeMap[p.Protocol])
	// Reserved (zero)
	bytes[2] = 0
	// Reserved (zero)
	bytes[3] = 0
	// Internal Port
	binary.BigEndian.PutUint16(bytes[4:6], p.InternalPort)
	// External Port
	binary.BigEndian.PutUint16(bytes[6:8], p.SuggestedExternalPort)
	// Lifetime in Seconds
	binary.BigEndian.PutUint32(bytes[8:12], p.RequestedLifetimeInSeconds)

	return bytes
}

func (p *PortMappingRequest) fromBytes(bytes []byte) error {
	if len(bytes) < 12 {
		return fmt.Errorf("invalid byte length of payload, was expecting 12, got %d", len(bytes))
	}

	protocol, exists := opCodeProtocolMap[opCode(bytes[1])]
	if !exists {
		return fmt.Errorf("unknown opcode protocol: %d", bytes[1])
	}

	// Protocol
	p.Protocol = protocol
	// Internal Port
	p.InternalPort = binary.BigEndian.Uint16(bytes[4:6])
	// External Port
	p.SuggestedExternalPort = binary.BigEndian.Uint16(bytes[4:6])
	// Lifetime in Seconds
	p.RequestedLifetimeInSeconds = binary.BigEndian.Uint32(bytes[8:12])

	return nil
}

type ExternalAddressResponse struct {
	ResultCode      Result
	Epoch           uint32
	ExternalAddress net.IP
}

func (e *ExternalAddressResponse) toBytes() []byte {
	bytes := make([]byte, 16)
	// Version
	bytes[0] = 0
	// OpCode
	bytes[1] = 0 | 0x80
	// ResultCode
	binary.BigEndian.PutUint16(bytes[2:4], uint16(e.ResultCode))
	// Epoch
	binary.BigEndian.PutUint32(bytes[4:8], e.Epoch)
	// External Address
	copy(bytes[8:12], e.ExternalAddress)

	return bytes
}

func (e *ExternalAddressResponse) fromBytes(bytes []byte) error {
	if len(bytes) < 12 {
		return fmt.Errorf("invalid byte length of payload, was expecting 12, got %d", len(bytes))
	}
	e.ResultCode = Result(binary.BigEndian.Uint16(bytes[2:4]))
	e.Epoch = binary.BigEndian.Uint32(bytes[4:8])
	e.ExternalAddress = bytes[8:12]
	return nil
}
