package natpmp

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"time"
)

// CreateSuccessResponse creates a NAT-PMP success response
func CreateSuccessResponse(opcode byte, internalPort, externalPort uint16, lifetime uint32) []byte {
	response := make([]byte, 16)
	response[0] = VersionNATPMP                                          // Version
	response[1] = opcode + 128                                           // Response opcode (128 + request opcode)
	binary.BigEndian.PutUint16(response[2:4], ResultSuccess)             // Result code: success
	binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix())) // Seconds since epoch
	binary.BigEndian.PutUint16(response[8:10], internalPort)
	binary.BigEndian.PutUint16(response[10:12], externalPort)
	binary.BigEndian.PutUint32(response[12:16], lifetime)
	return response
}

// CreateErrorResponse creates a NAT-PMP error response
func CreateErrorResponse(opcode byte, resultCode uint16) []byte {
	var response []byte

	if opcode == OpcodePublicAddress {
		// PUBLIC_ADDRESS error response (12 bytes)
		response = make([]byte, 12)
		response[0] = VersionNATPMP // Version
		response[1] = opcode + 128  // Response opcode (128 + request opcode)
		binary.BigEndian.PutUint16(response[2:4], resultCode)
		binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))
		// Bytes 8-11 are zeros
	} else {
		// MAP error response (16 bytes)
		response = make([]byte, 16)
		response[0] = VersionNATPMP // Version
		response[1] = opcode + 128  // Response opcode
		binary.BigEndian.PutUint16(response[2:4], resultCode)
		binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))
		// Bytes 8-15 are zeros
	}

	return response
}

// CreateUnsupportedVersionResponse creates an UNSUPP_VERSION response
// This tells clients we only support version 0 (NAT-PMP)
func CreateUnsupportedVersionResponse(requestOpcode byte) []byte {
	// UNSUPP_VERSION response (24 bytes minimum) - RFC 6887 Section 7.1
	response := make([]byte, 24)
	response[0] = VersionNATPMP           // Version: 0 (NAT-PMP) - tells client what version we support
	response[1] = 0x80                    // R=1 (response bit)
	response[1] |= (requestOpcode & 0x7F) // Copy opcode from request
	response[3] = ResultUnsuppVersion     // Result Code: UNSUPP_VERSION (1)
	// Lifetime at bytes 4-7: set to 0 for error response
	binary.BigEndian.PutUint32(response[4:8], 0)
	// Epoch time at bytes 8-11
	binary.BigEndian.PutUint32(response[8:12], uint32(time.Now().Unix()))
	// Reserved bytes 12-23 remain zero
	return response
}

// HandlerFunc is a callback function for handling NAT-PMP requests
type HandlerFunc func(req *Request, clientAddr net.IP) ([]byte, error)

// Server is a NAT-PMP server that handles requests via registered callbacks
type Server struct {
	listenAddr string
	conn       *net.UDPConn

	// Handler callbacks for each opcode
	publicAddressHandler HandlerFunc
	mapUDPHandler        HandlerFunc
	mapTCPHandler        HandlerFunc
}

// NewServer creates a new NAT-PMP server
func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
	}
}

// OnPublicAddress registers a handler for PUBLIC_ADDRESS requests (opcode 0)
func (s *Server) OnPublicAddress(handler HandlerFunc) {
	s.publicAddressHandler = handler
}

// OnMapUDP registers a handler for MAP_UDP requests (opcode 1)
func (s *Server) OnMapUDP(handler HandlerFunc) {
	s.mapUDPHandler = handler
}

// OnMapTCP registers a handler for MAP_TCP requests (opcode 2)
func (s *Server) OnMapTCP(handler HandlerFunc) {
	s.mapTCPHandler = handler
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
	s.conn = conn

	slog.Info("NAT-PMP server started", "listen_addr", s.listenAddr)

	go s.serve(ctx)
	return nil
}

// Stop stops the server
func (s *Server) Stop() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *Server) serve(ctx context.Context) {
	buffer := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read timeout
		s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Error("failed to read from UDP", "error", err)
			continue
		}

		// Copy data to avoid race condition when handling in goroutine
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Handle request in a goroutine
		go s.handleRequest(dataCopy, remoteAddr)
	}
}

func (s *Server) handleRequest(data []byte, remoteAddr *net.UDPAddr) {
	req, err := ParseRequest(data)
	if err != nil {
		slog.Warn("received invalid NAT-PMP request", "from", remoteAddr, "error", err)
		return
	}

	slog.Debug("Received NAT-PMP request", "version", req.Version, "opcode", req.Opcode, "from", remoteAddr)

	// Handle non NATPMP (version 1) requests - send UNSUPP_VERSION to trigger client fallback to NAT-PMP
	if req.Version != VersionNATPMP {
		slog.Debug("Sending UNSUPP_VERSION response", "requested_version", req.Version, "from", remoteAddr)
		response := CreateUnsupportedVersionResponse(req.Opcode)
		s.sendResponse(response, remoteAddr)
		return
	}

	// Route to the appropriate handler
	var response []byte
	var handlerErr error

	switch req.Opcode {
	case OpcodePublicAddress:
		slog.Debug("Routing to PUBLIC_ADDRESS handler", "from", remoteAddr)
		if s.publicAddressHandler != nil {
			response, handlerErr = s.publicAddressHandler(req, remoteAddr.IP)
		} else {
			slog.Warn("no handler registered for PUBLIC_ADDRESS", "from", remoteAddr)
			response = CreateErrorResponse(req.Opcode, ResultUnsuppOpcode)
		}
	case OpcodeMapUDP:
		slog.Debug("Routing to MAP_UDP handler", "from", remoteAddr, "internal_port", req.InternalPort, "lifetime", req.Lifetime)
		if s.mapUDPHandler != nil {
			response, handlerErr = s.mapUDPHandler(req, remoteAddr.IP)
		} else {
			slog.Warn("no handler registered for MAP_UDP", "from", remoteAddr)
			response = CreateErrorResponse(req.Opcode, ResultUnsuppOpcode)
		}
	case OpcodeMapTCP:
		slog.Debug("Routing to MAP_TCP handler", "from", remoteAddr, "internal_port", req.InternalPort, "lifetime", req.Lifetime)
		if s.mapTCPHandler != nil {
			response, handlerErr = s.mapTCPHandler(req, remoteAddr.IP)
		} else {
			slog.Warn("no handler registered for MAP_TCP", "from", remoteAddr)
			response = CreateErrorResponse(req.Opcode, ResultUnsuppOpcode)
		}
	default:
		slog.Warn("received NAT-PMP request with unknown opcode", "opcode", req.Opcode, "from", remoteAddr)
		response = CreateErrorResponse(req.Opcode, ResultUnsuppOpcode)
	}

	// If handler returned an error, send error response
	if handlerErr != nil {
		slog.Error("handler error", "error", handlerErr, "opcode", req.Opcode, "from", remoteAddr)
		response = CreateErrorResponse(req.Opcode, ResultNetworkFailure)
	}

	// Send response
	if response != nil {
		s.sendResponse(response, remoteAddr)
	} else {
		slog.Warn("no response generated for request", "opcode", req.Opcode, "from", remoteAddr)
	}
}

func (s *Server) sendResponse(response []byte, remoteAddr *net.UDPAddr) {
	s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := s.conn.WriteToUDP(response, remoteAddr)
	if err != nil {
		slog.Error("failed to send response to client", "error", err, "to", remoteAddr)
	}
}
