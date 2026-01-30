package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
	"github.com/features-not-bugs/mikrotik-double-natpmp/natpmp"
	"github.com/features-not-bugs/mikrotik-double-natpmp/utility"
)

var slog = utility.GetLogger().With("component", "mapper")

// mapping represents a complete double-NAT port mapping
type mapping struct {
	// Client information
	ClientIP     net.IP
	Protocol     natpmp.Protocol
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

	// Expiration timer - fires when mapping expires
	expirationTimer *time.Timer
}

// key uniquely identifies a mapping
type key struct {
	ClientIP     string
	Protocol     natpmp.Protocol
	InternalPort uint16
}

// mapper manages all port mappings with double-NAT support
type mapper struct {
	config              *config.Config
	mikrotik            *mikrotik.Client
	vpnGatewayNATClient *natpmp.Client
	server              *natpmp.Server

	// Mapping storage
	mu       sync.RWMutex
	mappings map[key]*mapping
	keyLocks sync.Map // map[key]*sync.Mutex - per-key locks for serializing operations
}

// newMapper creates a new mapping service
func newMapper(cfg *config.Config, mikroTikClient *mikrotik.Client) *mapper {
	m := &mapper{
		config:              cfg,
		mikrotik:            mikroTikClient,
		vpnGatewayNATClient: natpmp.NewClient(cfg.VpnGateway),
		mappings:            make(map[key]*mapping),
	}

	// Create NAT-PMP server with handlers
	m.server = natpmp.NewServer(
		cfg.ListenAddr,
		m.handleExternalAddress,
		m.handlePortMapping,
	)

	return m
}

// getKeyLock returns the mutex for a specific key, creating one if needed.
// This serializes all operations on the same mapping.
func (s *mapper) getKeyLock(k key) *sync.Mutex {
	lock, _ := s.keyLocks.LoadOrStore(k, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// Start starts the NAT-PMP server
func (s *mapper) Start(ctx context.Context) error {
	return s.server.Start(ctx)
}

// Stop stops the NAT-PMP server and cleans up all mappings
func (s *mapper) Stop() error {
	// First stop the server to prevent new requests
	if err := s.server.Stop(); err != nil {
		return err
	}

	// Copy all mappings while holding lock
	s.mu.Lock()
	mappingsToDelete := make([]*mapping, 0, len(s.mappings))
	for _, mapping := range s.mappings {
		// Stop expiration timer
		if mapping.expirationTimer != nil {
			mapping.expirationTimer.Stop()
		}
		mappingCopy := *mapping
		mappingsToDelete = append(mappingsToDelete, &mappingCopy)
	}
	// Clear the map
	s.mappings = make(map[key]*mapping)
	s.mu.Unlock()

	if len(mappingsToDelete) == 0 {
		slog.Info("No mappings to clean up")
		return nil
	}

	slog.Info("Cleaning up all mappings on shutdown", "count", len(mappingsToDelete))

	// Delete external resources without holding lock
	for _, mapping := range mappingsToDelete {
		// Delete from local MikroTik using rule ID (faster than searching by comment)
		if err := s.mikrotik.DeletePortMappingByID(mapping.MikroTikRuleID); err != nil {
			slog.Error("Failed to delete local mapping during shutdown",
				"error", err,
				"rule_id", mapping.MikroTikRuleID)
		}

		// Delete VPN mapping
		deleteReq := &natpmp.PortMappingRequest{
			Protocol:                   mapping.Protocol,
			InternalPort:               mapping.LocalExternalPort,
			SuggestedExternalPort:      0,
			RequestedLifetimeInSeconds: 0,
		}
		if _, err := s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq); err != nil {
			slog.Error("Failed to delete VPN mapping during shutdown", "error", err)
		}
	}

	slog.Info("All mappings cleaned up")
	return nil
}

// handleExternalAddress returns the external IP address
func (s *mapper) handleExternalAddress(clientIP net.IP) *natpmp.ExternalAddressResponse {
	response, err := s.vpnGatewayNATClient.GetExternalAddress()
	if err != nil {
		slog.Error("failed to request external address from vpn gateway", "client_ip", clientIP, "error", err)
		response = &natpmp.ExternalAddressResponse{
			ResultCode:      natpmp.ResultNetworkFailure,
			Epoch:           uint32(time.Now().Unix()),
			ExternalAddress: net.IPv4(0, 0, 0, 0),
		}
	} else {
		slog.Info("Handled external address request", "external_address", response.ExternalAddress)
	}
	return response
}

// handlePortMapping processes a NAT-PMP port mapping request
func (s *mapper) handlePortMapping(request *natpmp.PortMappingRequest, remoteIP net.IP) *natpmp.PortMappingResponse {
	clientIP := remoteIP.String()

	slog.Debug("Port mapping request",
		"client_ip", clientIP,
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"suggested_external_port", request.SuggestedExternalPort,
		"lifetime", request.RequestedLifetimeInSeconds)

	k := key{
		ClientIP:     clientIP,
		Protocol:     request.Protocol,
		InternalPort: request.InternalPort,
	}

	// Serialize all operations on this specific mapping
	keyLock := s.getKeyLock(k)
	keyLock.Lock()
	defer keyLock.Unlock()

	// Check if this is a deletion request
	if request.RequestedLifetimeInSeconds == 0 {
		return s.handlePortMappingDeletion(request, clientIP, k)
	}

	// Check if this is a renewal
	s.mu.RLock()
	existingMapping, isRenewal := s.mappings[k]
	s.mu.RUnlock()

	if isRenewal {
		// Copy the mapping data while holding the lock to avoid races
		mappingCopy := *existingMapping
		return s.handlePortMappingRenewal(&mappingCopy, request)
	}

	// Create new mapping
	return s.handlePortMappingCreation(request, clientIP, k)
}

// handlePortMappingCreation creates a new port mapping
// Caller must hold the key lock.
func (s *mapper) handlePortMappingCreation(request *natpmp.PortMappingRequest, clientIP string, k key) *natpmp.PortMappingResponse {
	// Create transaction for rollback support
	tx := utility.NewTransaction()
	defer func() {
		if tx != nil && !tx.Committed() {
			if err := tx.Rollback(); err != nil {
				slog.Error("Failed to rollback transaction", "error", err)
			}
		}
	}()

	// Step 1: Create mapping on local router via MikroTik API
	protocolStr := protocolToString(request.Protocol)

	slog.Debug("Sending to local gateway (MikroTik)",
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"suggested_external_port", request.SuggestedExternalPort)

	// Try to add port mapping with suggested port
	localResult, err := s.mikrotik.AddPortMapping(
		protocolStr,
		int(request.InternalPort),
		int(request.SuggestedExternalPort),
		request.RequestedLifetimeInSeconds,
		clientIP,
	)

	// If the suggested port is unavailable, find an available port
	if err != nil && (request.SuggestedExternalPort != 0) {
		slog.Debug("Suggested port unavailable, searching for alternative",
			"suggested_port", request.SuggestedExternalPort,
			"error", err)

		availablePort, findErr := s.mikrotik.FindAvailablePort(protocolStr, int(request.SuggestedExternalPort))
		if findErr != nil {
			slog.Error("Failed to find available port", "error", findErr)
			return &natpmp.PortMappingResponse{
				Protocol:     request.Protocol,
				ResultCode:   natpmp.ResultOutOfResources,
				Epoch:        uint32(time.Now().Unix()),
				InternalPort: request.InternalPort,
			}
		}

		slog.Debug("Found available port", "port", availablePort)

		// Retry with available port
		localResult, err = s.mikrotik.AddPortMapping(
			protocolStr,
			int(request.InternalPort),
			availablePort,
			request.RequestedLifetimeInSeconds,
			clientIP,
		)
	}

	if err != nil {
		slog.Error("Local gateway failed", "error", err)
		return &natpmp.PortMappingResponse{
			Protocol:     request.Protocol,
			ResultCode:   natpmp.ResultNetworkFailure,
			Epoch:        uint32(time.Now().Unix()),
			InternalPort: request.InternalPort,
		}
	}

	slog.Debug("Received from local gateway (MikroTik)",
		"assigned_external_port", localResult.ExternalPort,
		"rule_id", localResult.RuleID)

	// Add rollback for local mapping
	tx.AddRollback(func() error {
		slog.Debug("Rolling back local port mapping",
			"internal_port", request.InternalPort,
			"external_port", localResult.ExternalPort)
		return s.mikrotik.DeletePortMappingByID(localResult.RuleID)
	})

	// Step 2: Create mapping on VPN gateway
	slog.Debug("Sending to VPN gateway",
		"protocol", protocolName(request.Protocol),
		"internal_port", localResult.ExternalPort)

	vpnRequest := &natpmp.PortMappingRequest{
		Protocol:                   request.Protocol,
		InternalPort:               localResult.ExternalPort,
		SuggestedExternalPort:      0,
		RequestedLifetimeInSeconds: request.RequestedLifetimeInSeconds,
	}

	vpnResult, err := s.vpnGatewayNATClient.SendPortMappingRequest(vpnRequest)
	if err != nil {
		slog.Error("VPN gateway failed", "error", err)
		return &natpmp.PortMappingResponse{
			Protocol:     request.Protocol,
			ResultCode:   natpmp.ResultNetworkFailure,
			Epoch:        uint32(time.Now().Unix()),
			InternalPort: request.InternalPort,
		}
	}

	slog.Debug("Received from VPN gateway",
		"assigned_external_port", vpnResult.ExternalPort,
		"granted_lifetime", vpnResult.Lifetime)

	// Add rollback for VPN mapping
	tx.AddRollback(func() error {
		slog.Debug("Rolling back VPN port mapping",
			"internal_port", localResult.ExternalPort,
			"external_port", vpnResult.ExternalPort)
		deleteReq := &natpmp.PortMappingRequest{
			Protocol:                   request.Protocol,
			InternalPort:               localResult.ExternalPort,
			SuggestedExternalPort:      0,
			RequestedLifetimeInSeconds: 0,
		}
		_, err := s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq)
		return err
	})

	// Step 3: Store mapping
	now := time.Now()
	mapping := &mapping{
		ClientIP:          net.ParseIP(clientIP),
		Protocol:          request.Protocol,
		InternalPort:      request.InternalPort,
		LocalExternalPort: localResult.ExternalPort,
		MikroTikRuleID:    localResult.RuleID,
		VpnExternalPort:   vpnResult.ExternalPort,
		Lifetime:          vpnResult.Lifetime,
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Duration(vpnResult.Lifetime) * time.Second),
	}

	s.addMapping(mapping)

	// Commit transaction
	tx.Commit()

	slog.Info("Mapped port",
		"client", clientIP,
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"external_port", vpnResult.ExternalPort,
		"lifetime", vpnResult.Lifetime)

	return &natpmp.PortMappingResponse{
		Protocol:     request.Protocol,
		ResultCode:   natpmp.ResultSuccess,
		Epoch:        uint32(time.Now().Unix()),
		InternalPort: request.InternalPort,
		ExternalPort: vpnResult.ExternalPort,
		Lifetime:     vpnResult.Lifetime,
	}
}

// handlePortMappingDeletion deletes a port mapping
// Caller must hold the key lock.
func (s *mapper) handlePortMappingDeletion(request *natpmp.PortMappingRequest, clientIP string, k key) *natpmp.PortMappingResponse {
	// Get and remove mapping from state
	s.mu.Lock()
	existingMapping, exists := s.mappings[k]
	if !exists {
		s.mu.Unlock()
		// Mapping doesn't exist - return success (idempotent)
		return &natpmp.PortMappingResponse{
			Protocol:     request.Protocol,
			ResultCode:   natpmp.ResultSuccess,
			Epoch:        uint32(time.Now().Unix()),
			InternalPort: request.InternalPort,
			ExternalPort: 0,
			Lifetime:     0,
		}
	}

	// Stop expiration timer
	if existingMapping.expirationTimer != nil {
		existingMapping.expirationTimer.Stop()
	}

	mappingCopy := *existingMapping
	delete(s.mappings, k)
	s.mu.Unlock()

	// Delete from local MikroTik using rule ID
	if err := s.mikrotik.DeletePortMappingByID(mappingCopy.MikroTikRuleID); err != nil {
		slog.Error("Failed to delete local port mapping",
			"error", err,
			"protocol", protocolName(request.Protocol),
			"internal_port", request.InternalPort,
			"rule_id", mappingCopy.MikroTikRuleID)
	}

	// Delete VPN mapping
	deleteReq := &natpmp.PortMappingRequest{
		Protocol:                   request.Protocol,
		InternalPort:               mappingCopy.LocalExternalPort,
		SuggestedExternalPort:      0,
		RequestedLifetimeInSeconds: 0,
	}
	if _, err := s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq); err != nil {
		slog.Error("Failed to delete VPN port mapping",
			"error", err,
			"protocol", protocolName(request.Protocol),
			"internal_port", mappingCopy.LocalExternalPort)
	}

	slog.Info("Unmapped port",
		"client", clientIP,
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort)

	return &natpmp.PortMappingResponse{
		Protocol:     request.Protocol,
		ResultCode:   natpmp.ResultSuccess,
		Epoch:        uint32(time.Now().Unix()),
		InternalPort: request.InternalPort,
		ExternalPort: 0,
		Lifetime:     0,
	}
}

// handlePortMappingRenewal renews an existing port mapping
func (s *mapper) handlePortMappingRenewal(mapping *mapping, request *natpmp.PortMappingRequest) *natpmp.PortMappingResponse {
	slog.Debug("Client renewal request",
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"lifetime", request.RequestedLifetimeInSeconds)

	// MikroTik rule persists - no need to recreate
	// Only renew the VPN gateway mapping
	vpnRequest := &natpmp.PortMappingRequest{
		Protocol:                   request.Protocol,
		InternalPort:               mapping.LocalExternalPort,
		SuggestedExternalPort:      mapping.VpnExternalPort,
		RequestedLifetimeInSeconds: request.RequestedLifetimeInSeconds,
	}

	vpnResult, err := s.vpnGatewayNATClient.SendPortMappingRequest(vpnRequest)
	if err != nil {
		slog.Error("VPN renewal failed", "error", err)
		return &natpmp.PortMappingResponse{
			Protocol:     request.Protocol,
			ResultCode:   natpmp.ResultNetworkFailure,
			Epoch:        uint32(time.Now().Unix()),
			InternalPort: request.InternalPort,
		}
	}

	// Update mapping
	s.mu.Lock()
	defer s.mu.Unlock()

	key := key{
		ClientIP:     mapping.ClientIP.String(),
		Protocol:     request.Protocol,
		InternalPort: request.InternalPort,
	}
	if m, exists := s.mappings[key]; exists {
		// Stop old timer
		if m.expirationTimer != nil {
			m.expirationTimer.Stop()
		}

		// Update mapping fields
		m.Lifetime = vpnResult.Lifetime
		m.ExpiresAt = time.Now().Add(time.Duration(vpnResult.Lifetime) * time.Second)
		m.VpnExternalPort = vpnResult.ExternalPort

		// Set new expiration timer
		duration := time.Until(m.ExpiresAt)
		if duration < 0 {
			duration = 0
		}
		m.expirationTimer = time.AfterFunc(duration, func() {
			s.expireMapping(key)
		})

		slog.Debug("Updated expiration timer", "expires_in", duration)
	}

	slog.Info("Mapping renewed",
		"client", mapping.ClientIP,
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"lifetime", vpnResult.Lifetime)

	return &natpmp.PortMappingResponse{
		Protocol:     request.Protocol,
		ResultCode:   natpmp.ResultSuccess,
		Epoch:        uint32(time.Now().Unix()),
		InternalPort: request.InternalPort,
		ExternalPort: vpnResult.ExternalPort,
		Lifetime:     vpnResult.Lifetime,
	}
}

func (s *mapper) addMapping(mapping *mapping) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := key{
		ClientIP:     mapping.ClientIP.String(),
		Protocol:     mapping.Protocol,
		InternalPort: mapping.InternalPort,
	}

	// Set up expiration timer for this mapping
	duration := time.Until(mapping.ExpiresAt)
	if duration < 0 {
		duration = 0 // Expire immediately
	}

	mapping.expirationTimer = time.AfterFunc(duration, func() {
		s.expireMapping(key)
	})

	s.mappings[key] = mapping

	slog.Debug("Added mapping to state",
		"client_ip", mapping.ClientIP,
		"protocol", protocolName(mapping.Protocol),
		"internal_port", mapping.InternalPort,
		"expires_in", duration)
}

// expireMapping removes an expired mapping and cleans up resources
func (s *mapper) expireMapping(k key) {
	// Serialize with any concurrent operations on this key
	keyLock := s.getKeyLock(k)
	keyLock.Lock()
	defer keyLock.Unlock()

	s.mu.Lock()
	mapping, exists := s.mappings[k]
	if !exists {
		s.mu.Unlock()
		return // Already deleted
	}

	// Copy data before releasing lock
	mappingCopy := *mapping
	delete(s.mappings, k)
	s.mu.Unlock()

	slog.Info("Mapping expired",
		"client", mappingCopy.ClientIP,
		"protocol", protocolName(mappingCopy.Protocol),
		"internal_port", mappingCopy.InternalPort)

	// Delete from local MikroTik using rule ID
	if err := s.mikrotik.DeletePortMappingByID(mappingCopy.MikroTikRuleID); err != nil {
		slog.Error("Failed to delete expired local port mapping",
			"error", err,
			"protocol", protocolName(mappingCopy.Protocol),
			"internal_port", mappingCopy.InternalPort,
			"client_ip", mappingCopy.ClientIP,
			"rule_id", mappingCopy.MikroTikRuleID)
	}

	// Delete VPN mapping
	deleteReq := &natpmp.PortMappingRequest{
		Protocol:                   mappingCopy.Protocol,
		InternalPort:               mappingCopy.LocalExternalPort,
		SuggestedExternalPort:      0,
		RequestedLifetimeInSeconds: 0,
	}
	if _, err := s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq); err != nil {
		slog.Error("Failed to delete expired VPN port mapping",
			"error", err,
			"protocol", protocolName(mappingCopy.Protocol),
			"internal_port", mappingCopy.LocalExternalPort)
	}
}

// ReconcileRules removes stale MikroTik rules that are not tracked in state
// This is a safety net to catch any rules that weren't cleaned up properly
// (e.g., due to crashes, network issues during cleanup, etc.)
func (s *mapper) ReconcileRules() error {
	// Get all our rules from MikroTik
	rules, err := s.mikrotik.GetAllDoubleNATPMPRules()
	if err != nil {
		return err
	}

	if len(rules) == 0 {
		return nil
	}

	// Build set of tracked rule IDs
	s.mu.RLock()
	trackedRules := make(map[string]bool)
	for _, mapping := range s.mappings {
		if mapping.MikroTikRuleID != "" {
			trackedRules[mapping.MikroTikRuleID] = true
		}
	}
	s.mu.RUnlock() // Note: defer not used to minimize lock hold time during rule iteration

	// Check each rule against our state
	removedCount := 0
	for _, rule := range rules {
		if !trackedRules[rule.ID] {
			slog.Warn("Found orphaned MikroTik rule, removing",
				"rule_id", rule.ID,
				"protocol", rule.Protocol,
				"dst_port", rule.DstPort,
				"to_address", rule.ToAddress,
				"comment", rule.Comment)

			if err := s.mikrotik.DeleteRuleByID(rule.ID); err != nil {
				slog.Error("Failed to delete orphaned rule", "rule_id", rule.ID, "error", err)
			} else {
				removedCount++
			}
		}
	}

	if removedCount > 0 {
		slog.Info("Reconciliation removed orphaned rules", "removed", removedCount)
	}

	return nil
}

// Helper functions

func protocolToString(protocol natpmp.Protocol) string {
	if protocol == natpmp.ProtocolTCP {
		return "tcp"
	}
	return "udp"
}

func protocolName(protocol natpmp.Protocol) string {
	if protocol == natpmp.ProtocolTCP {
		return "TCP"
	}
	return "UDP"
}
