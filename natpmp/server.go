package natpmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/utility"
)

var slog = utility.GetLogger().With("component", "natpmp-server")

type ExternalAddressHandler func(remoteIP net.IP) *ExternalAddressResponse
type PortMappingHandler func(request *PortMappingRequest, remoteIP net.IP) *PortMappingResponse

// Server is a NAT-PMP server that handles requests via registered callbacks
type Server struct {
	listenAddr             string
	conn                   *net.UDPConn
	externalAddressHandler ExternalAddressHandler
	portMappingHandler     PortMappingHandler
	mu                     sync.RWMutex  // Protects conn
	sem                    chan struct{} // Semaphore to limit concurrent handlers
}

// NewServer creates a new NAT-PMP server
func NewServer(listenAddr string, externalAddressHandler ExternalAddressHandler, portMappingHandler PortMappingHandler) *Server {
	const maxConcurrentHandlers = 100
	return &Server{
		listenAddr:             listenAddr,
		externalAddressHandler: externalAddressHandler,
		portMappingHandler:     portMappingHandler,
		sem:                    make(chan struct{}, maxConcurrentHandlers),
	}
}

// Start begins listening for NAT-PMP requests
func (s *Server) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", s.listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock() // Note: defer not used for minimal lock hold time

	go s.serve(ctx)
	return nil
}

// Stop stops the server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil // Prevent double-close
		return err
	}
	return nil
}

func (s *Server) serve(ctx context.Context) {
	slog.Info("Server started", "listen_addr", s.listenAddr)
	buffer := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Server stopped", "listen_addr", s.listenAddr)
			return
		default:
		}

		// Get conn with lock protection
		s.mu.RLock()
		conn := s.conn
		s.mu.RUnlock() // Note: defer not used for minimal lock hold time in hot loop

		if conn == nil {
			return
		}

		// Set read timeout
		err := conn.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			slog.Error("failed to set read deadline when listening for natpmp messages", "error", err)
			continue
		}

		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			slog.Error("failed to read from UDP", "error", err)
			continue
		}

		// Copy data to avoid race condition when handling in goroutine
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Try to acquire semaphore (non-blocking)
		select {
		case s.sem <- struct{}{}:
			// Handle request in a goroutine
			go func() {
				defer func() { <-s.sem }()
				s.handleRequest(dataCopy, remoteAddr)
			}()
		default:
			// Too many concurrent requests, drop this one
			slog.Warn("dropping request due to max concurrent handlers", "from", remoteAddr)
		}
	}
}

func (s *Server) handleRequest(data []byte, remoteAddr *net.UDPAddr) {
	if len(data) < 2 {
		slog.Debug("received invalid request", "from", remoteAddr, "error", "data less than 2 bytes long")
		return
	}

	version := data[0]
	opcode := data[1]

	slog.Debug("Received request", "version", version, "opcode", opcode, "from", remoteAddr)

	// we only handle version 0 requests - send unsupported version response to trigger client fallback to version 0
	if version != 0 {
		slog.Debug("Sending UNSUPP_VERSION response", "requested_version", version, "from", remoteAddr)
		response := createUnsupportedVersionResponse()
		s.sendResponse(response, remoteAddr)
		return
	}

	// https://datatracker.ietf.org/doc/html/rfc6886
	// If the opcode in the request is 128 or greater, then this is not a request; it's a response, and the NAT-PMP server MUST silently ignore it.
	if opcode > 127 {
		slog.Debug("ignoring response packet received on server", "from", remoteAddr, "opcode", opcode)
		return
	}

	// Route to the appropriate handler
	var response []byte

	switch opcode {
	case byte(opcodePublicAddress):
		slog.Debug("routing to external address handler", "from", remoteAddr)
		if s.externalAddressHandler == nil {
			response = createUnsupportedOpcodeResponse(data)
			break
		}
		externalAddressResponse := s.externalAddressHandler(remoteAddr.IP)
		response = externalAddressResponse.toBytes()
	case byte(opcodeMapUDP):
		fallthrough
	case byte(opcodeMapTCP):
		slog.Debug("routing to port mapping handler", "from", remoteAddr)
		if s.portMappingHandler == nil {
			response = createUnsupportedOpcodeResponse(data)
			break
		}
		portMappingRequest := &PortMappingRequest{}
		err := portMappingRequest.fromBytes(data)
		if err != nil {
			// Malformed request, lets just drop it...
			slog.Debug("received malformed request", "from", remoteAddr, "err", err)
			return
		}
		portMappingResponse := s.portMappingHandler(portMappingRequest, remoteAddr.IP)
		response = portMappingResponse.toBytes()

	default:
		slog.Warn("received request with unknown opcode", "opcode", opcode, "from", remoteAddr)
		response = createUnsupportedOpcodeResponse(data)
	}

	// Send response
	if response != nil {
		s.sendResponse(response, remoteAddr)
	} else {
		slog.Error("no response generated for request", "opcode", opcode, "from", remoteAddr)
	}
}

func (s *Server) sendResponse(response []byte, remoteAddr *net.UDPAddr) {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock() // Note: defer not used for minimal lock hold time

	if conn == nil {
		slog.Error("connection closed, cannot send response", "to", remoteAddr)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.WriteToUDP(response, remoteAddr)
	if err != nil {
		slog.Error("failed to send response to client", "error", err, "to", remoteAddr)
	}
}

// createUnsupportedVersionResponse creates an Unsupported Version response
// This tells clients we only support version 0
func createUnsupportedVersionResponse() []byte {
	response := make([]byte, 8)
	// Version: 0 (the version we support)
	response[0] = 0
	// OpCode: 0 (per RFC 6886 Section 3.5)
	response[1] = 0
	// Result Code: 1 (Unsupported Version)
	binary.BigEndian.PutUint16(response[2:4], uint16(ResultUnsupportedVersion))
	// Seconds Since Start of Epoch
	binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))

	return response
}

// createUnsupportedOpCodeResponse creates an Unsupported OpCode response
// This tells clients we don't support that OpCode
func createUnsupportedOpcodeResponse(request []byte) []byte {
	// Response needs at least 4 bytes: version, opcode, result code (2 bytes)
	responseLen := len(request)
	if responseLen < 4 {
		responseLen = 4
	}

	response := make([]byte, responseLen)
	copy(response, request)

	// Version: 0
	response[0] = 0
	// Opcode with response bit set
	response[1] = request[1] | 0x80
	// Result Code: 5 (Unsupported Opcode)
	binary.BigEndian.PutUint16(response[2:4], uint16(ResultUnsupportedOpcode))

	return response
}
