package mapping

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
	"github.com/features-not-bugs/mikrotik-double-natpmp/natpmp"
)

const (
	protocolUDP = 1
	protocolTCP = 2
)

// Mapping represents a complete double-NAT port mapping
type Mapping struct {
	// Client information
	ClientIP     net.IP
	Protocol     byte // 1=UDP, 2=TCP
	InternalPort uint16

	// Local MikroTik mapping
	LocalExternalPort uint16
	MikroTikRuleID    string

	// VPN mapping
	VpnExternalPort uint16

	// Lifecycle
	Lifetime  uint32
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Key uniquely identifies a mapping
type Key struct {
	ClientIP     string
	Protocol     byte
	InternalPort uint16
}

// Service manages all port mappings with double-NAT support
type Service struct {
	config   *config.Config
	mikrotik *mikrotik.Client
	vpn      *natpmp.Client

	// Mapping storage
	mu       sync.RWMutex
	mappings map[Key]*Mapping

	// Request queues per internal port to serialize concurrent requests
	queuesMu sync.Mutex
	queues   map[string]chan *mappingRequest
}

// NewService creates a new mapping service
func NewService(cfg *config.Config, mikroTikClient *mikrotik.Client) *Service {
	return &Service{
		config:   cfg,
		mikrotik: mikroTikClient,
		vpn:      natpmp.NewClient(cfg.VpnGateway),
		mappings: make(map[Key]*Mapping),
		queues:   make(map[string]chan *mappingRequest),
	}
}

// Create creates a new port mapping
func (s *Service) Create(clientIP net.IP, protocol string, internalPort, suggestedExtPort uint16, lifetime uint32) error {
	// Build NAT-PMP request
	request := make([]byte, 12)
	request[0] = 0 // Version
	if protocol == "tcp" {
		request[1] = protocolTCP
	} else {
		request[1] = protocolUDP
	}
	binary.BigEndian.PutUint16(request[4:6], internalPort)
	binary.BigEndian.PutUint16(request[6:8], suggestedExtPort)
	binary.BigEndian.PutUint32(request[8:12], lifetime)

	_, err := s.HandleMapping(request, request[1], clientIP.String())
	return err
}

// Delete removes a port mapping
func (s *Service) Delete(clientIP net.IP, protocol string, internalPort uint16) error {
	// Build NAT-PMP deletion request (lifetime = 0)
	request := make([]byte, 12)
	request[0] = 0 // Version
	if protocol == "tcp" {
		request[1] = protocolTCP
	} else {
		request[1] = protocolUDP
	}
	binary.BigEndian.PutUint16(request[4:6], internalPort)
	binary.BigEndian.PutUint16(request[6:8], 0)
	binary.BigEndian.PutUint32(request[8:12], 0) // lifetime = 0 means delete

	_, err := s.HandleMapping(request, request[1], clientIP.String())
	return err
}

// Get retrieves a mapping
func (s *Service) Get(clientIP net.IP, protocol string, internalPort uint16) (*Mapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	protocolByte := byte(protocolUDP)
	if protocol == "tcp" {
		protocolByte = protocolTCP
	}

	key := Key{
		ClientIP:     clientIP.String(),
		Protocol:     protocolByte,
		InternalPort: internalPort,
	}

	mapping, ok := s.mappings[key]
	if !ok {
		return nil, fmt.Errorf("mapping not found")
	}

	// Return a copy to avoid race conditions when caller accesses fields
	mappingCopy := *mapping
	return &mappingCopy, nil
}

// HandleMapping processes a port mapping request
func (s *Service) HandleMapping(data []byte, opcode byte, clientIP string) ([]byte, error) {
	if len(data) < 12 {
		return s.createErrorResponse(opcode, 5), fmt.Errorf("invalid request length")
	}

	// Extract internal port to determine queue
	internalPort := binary.BigEndian.Uint16(data[4:6])
	protocol := opcode // 1=UDP, 2=TCP

	queueKey := fmt.Sprintf("%d-%d", protocol, internalPort)

	// Get or create queue for this port
	queue := s.getOrCreateQueue(queueKey)

	// Send request to queue
	req := &mappingRequest{
		data:     data,
		opcode:   opcode,
		clientIP: clientIP,
		response: make(chan *mappingResponse, 1),
	}

	queue <- req

	// Wait for response
	resp := <-req.response
	return resp.data, resp.err
}

func (s *Service) getOrCreateQueue(key string) chan *mappingRequest {
	s.queuesMu.Lock()
	defer s.queuesMu.Unlock()

	if queue, exists := s.queues[key]; exists {
		return queue
	}

	queue := make(chan *mappingRequest, 100)
	s.queues[key] = queue

	// Start worker for this queue
	go s.processQueue(queue)

	return queue
}

type mappingRequest struct {
	data     []byte
	opcode   byte
	clientIP string
	response chan *mappingResponse
}

type mappingResponse struct {
	data []byte
	err  error
}

func (s *Service) processQueue(queue chan *mappingRequest) {
	for req := range queue {
		data, err := s.handleMappingRequest(req.data, req.opcode, req.clientIP)
		req.response <- &mappingResponse{
			data: data,
			err:  err,
		}
	}
}

func (s *Service) handleMappingRequest(data []byte, opcode byte, clientIP string) ([]byte, error) {
	// Parse request
	internalPort := binary.BigEndian.Uint16(data[4:6])
	suggestedExtPort := binary.BigEndian.Uint16(data[6:8])
	lifetime := binary.BigEndian.Uint32(data[8:12])

	protocol := opcode // 1=UDP, 2=TCP

	// Check if this is a deletion request
	if lifetime == 0 {
		return s.handleDeletion(protocol, internalPort, opcode, clientIP)
	}

	// Check if this is a renewal (mapping already exists)
	key := Key{
		ClientIP:     clientIP,
		Protocol:     protocol,
		InternalPort: internalPort,
	}
	s.mu.RLock()
	existingMapping, isRenewal := s.mappings[key]
	s.mu.RUnlock()

	if isRenewal {
		return s.handleRenewal(existingMapping, lifetime, opcode)
	}

	// Only log non-deletion/non-renewal requests to avoid spam
	slog.Info("Port forward request",
		"client_ip", clientIP,
		"protocol", protocolName(protocol),
		"internal_port", internalPort,
		"suggested_external_port", suggestedExtPort,
		"lifetime", lifetime)

	// Create transaction for rollback support
	tx := NewTransaction()
	defer func() {
		if tx != nil && !tx.committed {
			tx.Rollback()
		}
	}()

	// Step 1: Create mapping on local router via MikroTik API
	slog.Info("Sending to local gateway (MikroTik)",
		"protocol", protocolName(protocol),
		"internal_port", internalPort,
		"suggested_external_port", suggestedExtPort)

	protocolStr := "udp"
	if protocol == protocolTCP {
		protocolStr = "tcp"
	}

	localResult, err := s.mikrotik.AddPortMapping(protocolStr, int(internalPort), int(suggestedExtPort), lifetime, clientIP)
	if err != nil {
		slog.Error("Local gateway failed", "error", err)
		return s.createErrorResponse(opcode, 3), err
	}

	localExtPort := localResult.ExternalPort
	localRuleID := localResult.RuleID

	slog.Info("Received from local gateway (MikroTik)",
		"assigned_external_port", localExtPort,
		"rule_id", localRuleID)

	// Add rollback for local mapping
	tx.AddRollback(func() error {
		slog.Info("Rolling back local port mapping", "internal_port", internalPort, "external_port", localExtPort)
		return s.mikrotik.DeletePortMappingByID(localRuleID)
	})

	// Step 2: Create mapping on VPN gateway
	slog.Info("Sending to VPN gateway",
		"protocol", protocolName(protocol),
		"internal_port", localExtPort)

	vpnResult, err := s.vpn.AddPortMapping(protocolStr, int(localExtPort), 0, int(lifetime))
	if err != nil {
		slog.Error("VPN gateway failed", "error", err)
		return s.createErrorResponse(opcode, 3), err
	}

	vpnExtPort := vpnResult.ExternalPort

	slog.Info("Received from VPN gateway",
		"assigned_external_port", vpnExtPort,
		"granted_lifetime", vpnResult.Lifetime)

	// Add rollback for VPN mapping
	tx.AddRollback(func() error {
		slog.Info("Rolling back VPN port mapping", "internal_port", localExtPort, "external_port", vpnExtPort)
		return s.vpn.DeletePortMapping(protocolStr, int(localExtPort))
	})

	// Step 3: Store mapping and schedule renewal
	now := time.Now()
	mapping := &Mapping{
		ClientIP:          net.ParseIP(clientIP),
		Protocol:          protocol,
		InternalPort:      internalPort,
		LocalExternalPort: localExtPort,
		MikroTikRuleID:    localRuleID,
		VpnExternalPort:   vpnExtPort,
		Lifetime:          vpnResult.Lifetime,
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Duration(vpnResult.Lifetime) * time.Second),
	}

	s.addMapping(mapping)
	// Client is responsible for renewals based on the lifetime we return

	// Commit transaction (clears rollbacks)
	tx.Commit()

	slog.Info("Port opened",
		"protocol", protocolName(protocol),
		"internal_port", internalPort,
		"local_external_port", localExtPort,
		"vpn_external_port", vpnExtPort,
		"lifetime", vpnResult.Lifetime)

	// Create success response with VPN's external port
	return s.createSuccessResponse(opcode, internalPort, vpnExtPort, vpnResult.Lifetime), nil
}

func (s *Service) handleDeletion(protocol byte, internalPort uint16, opcode byte, clientIP string) ([]byte, error) {
	key := Key{
		ClientIP:     clientIP,
		Protocol:     protocol,
		InternalPort: internalPort,
	}

	s.mu.Lock()
	mapping, exists := s.mappings[key]
	if exists {
		delete(s.mappings, key)
	}
	s.mu.Unlock()

	if exists {
		// Delete MikroTik rule
		protocolStr := "udp"
		if protocol == protocolTCP {
			protocolStr = "tcp"
		}
		s.mikrotik.DeletePortMapping(protocolStr, int(internalPort), clientIP)

		// Delete VPN mapping
		s.vpn.DeletePortMapping(protocolStr, int(mapping.LocalExternalPort))

		slog.Info("Port closed",
			"protocol", protocolName(protocol),
			"internal_port", internalPort)
	}

	return s.createSuccessResponse(opcode, internalPort, 0, 0), nil
}

func (s *Service) addMapping(mapping *Mapping) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := Key{
		ClientIP:     mapping.ClientIP.String(),
		Protocol:     mapping.Protocol,
		InternalPort: mapping.InternalPort,
	}

	s.mappings[key] = mapping

	slog.Info("Added mapping to state",
		"client_ip", mapping.ClientIP,
		"protocol", mapping.Protocol,
		"internal_port", mapping.InternalPort,
		"local_external_port", mapping.LocalExternalPort,
		"vpn_external_port", mapping.VpnExternalPort,
		"mikrotik_rule_id", mapping.MikroTikRuleID)
}

// handleRenewal processes a client renewal request for an existing mapping
func (s *Service) handleRenewal(mapping *Mapping, newLifetime uint32, opcode byte) ([]byte, error) {
	slog.Info("Client renewal request",
		"protocol", protocolName(mapping.Protocol),
		"internal_port", mapping.InternalPort,
		"lifetime", newLifetime)

	protocolStr := "udp"
	if mapping.Protocol == protocolTCP {
		protocolStr = "tcp"
	}

	// Get the fields we need while holding the lock (mapping is a pointer to map entry)
	s.mu.RLock()
	localExtPort := mapping.LocalExternalPort
	vpnExtPort := mapping.VpnExternalPort
	clientIP := mapping.ClientIP.String()
	protocol := mapping.Protocol
	internalPort := mapping.InternalPort
	s.mu.RUnlock()

	// MikroTik rule persists - no need to recreate
	// Only renew the VPN gateway mapping
	vpnResult, err := s.vpn.AddPortMapping(
		protocolStr,
		int(localExtPort),
		int(vpnExtPort),
		int(newLifetime),
	)
	if err != nil {
		slog.Error("VPN renewal failed",
			"protocol", protocol,
			"internal_port", internalPort,
			"error", err)
		return s.createErrorResponse(opcode, 3), err
	}

	// Update mapping with new expiration
	s.mu.Lock()
	key := Key{
		ClientIP:     clientIP,
		Protocol:     protocol,
		InternalPort: internalPort,
	}
	// Verify mapping still exists
	if m, exists := s.mappings[key]; exists {
		m.Lifetime = vpnResult.Lifetime
		m.ExpiresAt = time.Now().Add(time.Duration(vpnResult.Lifetime) * time.Second)
		m.VpnExternalPort = vpnResult.ExternalPort
	}
	s.mu.Unlock()

	slog.Info("Renewal successful",
		"protocol", protocolName(protocol),
		"internal_port", internalPort,
		"vpn_external_port", vpnResult.ExternalPort,
		"lifetime", vpnResult.Lifetime)

	return s.createSuccessResponse(opcode, internalPort, vpnResult.ExternalPort, vpnResult.Lifetime), nil
}

// ReconcileRules removes MikroTik rules that are not tracked in state
// and cleans up expired mappings
func (s *Service) ReconcileRules() error {
	slog.Info("Starting reconciliation of MikroTik rules")

	// First, clean up expired mappings
	s.cleanupExpiredMappings()

	// Get all our rules from MikroTik
	rules, err := s.mikrotik.GetAllDoubleNATPMPRules()
	if err != nil {
		return err
	}

	slog.Info("Found MikroTik rules to reconcile", "count", len(rules))

	// Build set of tracked rule IDs
	s.mu.RLock()
	trackedRules := make(map[string]bool)
	for _, mapping := range s.mappings {
		if mapping.MikroTikRuleID != "" {
			trackedRules[mapping.MikroTikRuleID] = true
		}
	}
	s.mu.RUnlock()

	// Check each rule against our state
	removedCount := 0
	for _, rule := range rules {
		if !trackedRules[rule.ID] {
			slog.Info("Removing stale MikroTik rule",
				"rule_id", rule.ID,
				"protocol", rule.Protocol,
				"dst_port", rule.DstPort,
				"to_address", rule.ToAddress,
				"comment", rule.Comment)

			if err := s.mikrotik.DeleteRuleByID(rule.ID); err != nil {
				slog.Error("Failed to delete stale rule", "rule_id", rule.ID, "error", err)
			} else {
				removedCount++
			}
		}
	}

	slog.Info("Reconciliation complete",
		"total_rules", len(rules),
		"removed", removedCount,
		"kept", len(rules)-removedCount)

	return nil
}

// cleanupExpiredMappings removes mappings that have expired
func (s *Service) cleanupExpiredMappings() {
	now := time.Now()

	// First pass: identify expired mappings and copy data we need
	s.mu.Lock()
	type expiredMapping struct {
		key          Key
		protocol     byte
		internalPort uint16
		localExtPort uint16
		clientIP     string
	}

	expiredMappings := make([]expiredMapping, 0)
	for key, mapping := range s.mappings {
		if now.After(mapping.ExpiresAt) {
			expiredMappings = append(expiredMappings, expiredMapping{
				key:          key,
				protocol:     mapping.Protocol,
				internalPort: mapping.InternalPort,
				localExtPort: mapping.LocalExternalPort,
				clientIP:     mapping.ClientIP.String(),
			})
			slog.Info("Mapping expired",
				"protocol", protocolName(mapping.Protocol),
				"internal_port", mapping.InternalPort,
				"client_ip", mapping.ClientIP,
				"expired_at", mapping.ExpiresAt)
		}
	}

	// Delete from map while holding lock
	for _, expired := range expiredMappings {
		delete(s.mappings, expired.key)
	}
	s.mu.Unlock()

	// Second pass: cleanup external resources without holding lock
	for _, expired := range expiredMappings {
		protocolStr := "udp"
		if expired.protocol == protocolTCP {
			protocolStr = "tcp"
		}

		s.mikrotik.DeletePortMapping(protocolStr, int(expired.internalPort), expired.clientIP)
		s.vpn.DeletePortMapping(protocolStr, int(expired.localExtPort))

		slog.Info("Cleaned up expired mapping",
			"protocol", protocolName(expired.protocol),
			"internal_port", expired.internalPort)
	}

	if len(expiredMappings) > 0 {
		slog.Info("Expired mappings cleaned up", "count", len(expiredMappings))
	}
}

// DeleteAll removes all mappings (called on shutdown)
func (s *Service) DeleteAll() error {
	// Copy all mappings while holding lock
	s.mu.Lock()
	mappingsToDelete := make([]*Mapping, 0, len(s.mappings))
	for _, mapping := range s.mappings {
		mappingCopy := *mapping
		mappingsToDelete = append(mappingsToDelete, &mappingCopy)
	}
	// Clear the map
	s.mappings = make(map[Key]*Mapping)
	s.mu.Unlock()

	slog.Info("Deleting all mappings", "count", len(mappingsToDelete))

	// Delete external resources without holding lock
	for _, mapping := range mappingsToDelete {
		// Delete MikroTik rule
		protocolStr := "udp"
		if mapping.Protocol == protocolTCP {
			protocolStr = "tcp"
		}
		if err := s.mikrotik.DeletePortMapping(protocolStr, int(mapping.InternalPort), mapping.ClientIP.String()); err != nil {
			slog.Error("Failed to delete local mapping", "error", err)
		}

		// Delete VPN mapping
		if err := s.vpn.DeletePortMapping(protocolStr, int(mapping.LocalExternalPort)); err != nil {
			slog.Error("Failed to delete VPN mapping", "error", err)
		}
	}

	return nil
}

// Response helpers

func (s *Service) createSuccessResponse(opcode byte, internalPort, externalPort uint16, lifetime uint32) []byte {
	response := make([]byte, 16)
	response[0] = 0                                                      // Version
	response[1] = opcode + 128                                           // Response opcode (128 + request opcode)
	binary.BigEndian.PutUint16(response[2:4], 0)                         // Result code: success
	binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix())) // Seconds since epoch
	binary.BigEndian.PutUint16(response[8:10], internalPort)
	binary.BigEndian.PutUint16(response[10:12], externalPort)
	binary.BigEndian.PutUint32(response[12:16], lifetime)
	return response
}

func (s *Service) createErrorResponse(opcode byte, resultCode uint16) []byte {
	response := make([]byte, 16)
	response[0] = 0                                       // Version
	response[1] = opcode + 128                            // Response opcode
	binary.BigEndian.PutUint16(response[2:4], resultCode) // Result code
	binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))
	return response
}

func protocolName(protocol byte) string {
	if protocol == protocolTCP {
		return "TCP"
	}
	return "UDP"
}
