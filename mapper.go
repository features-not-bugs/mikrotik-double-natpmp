package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
	"github.com/features-not-bugs/mikrotik-double-natpmp/natpmp"
	"github.com/features-not-bugs/mikrotik-double-natpmp/utility"
)

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

// Start starts the NAT-PMP server
func (s *mapper) Start(ctx context.Context) error {
	return s.server.Start(ctx)
}

// Stop stops the NAT-PMP server
func (s *mapper) Stop() error {
	return s.server.Stop()
}

// handleExternalAddress returns the external IP address
func (s *mapper) handleExternalAddress(remoteIP net.IP) *natpmp.ExternalAddressResponse {
	return &natpmp.ExternalAddressResponse{
		ResultCode:      natpmp.ResultSuccess,
		Epoch:           uint32(time.Now().Unix()),
		ExternalAddress: s.config.VpnGateway.To4(),
	}
}

// handlePortMapping processes a NAT-PMP port mapping request
func (s *mapper) handlePortMapping(request *natpmp.PortMappingRequest, remoteIP net.IP) *natpmp.PortMappingResponse {
	clientIP := remoteIP.String()

	slog.Info("Port mapping request",
		"client_ip", clientIP,
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"suggested_external_port", request.SuggestedExternalPort,
		"lifetime", request.RequestedLifetimeInSeconds)

	// Check if this is a deletion request
	if request.RequestedLifetimeInSeconds == 0 {
		return s.handlePortMappingDeletion(request, clientIP)
	}

	// Check if this is a renewal
	key := key{
		ClientIP:     clientIP,
		Protocol:     request.Protocol,
		InternalPort: request.InternalPort,
	}

	s.mu.RLock()
	existingMapping, isRenewal := s.mappings[key]
	if isRenewal {
		// Copy the mapping data while holding the lock to avoid races
		mappingCopy := *existingMapping
		s.mu.RUnlock()
		return s.handlePortMappingRenewal(&mappingCopy, request)
	}
	s.mu.RUnlock()

	// Create new mapping
	return s.handlePortMappingCreation(request, clientIP)
}

// handlePortMappingCreation creates a new port mapping
func (s *mapper) handlePortMappingCreation(request *natpmp.PortMappingRequest, clientIP string) *natpmp.PortMappingResponse {
	// Create transaction for rollback support
	tx := utility.NewTransaction()
	defer func() {
		if tx != nil && !tx.Committed() {
			_ = tx.Rollback()
		}
	}()

	// Step 1: Create mapping on local router via MikroTik API
	protocolStr := protocolToString(request.Protocol)

	slog.Info("Sending to local gateway (MikroTik)",
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
		slog.Info("Suggested port unavailable, searching for alternative",
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

		slog.Info("Found available port", "port", availablePort)

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

	slog.Info("Received from local gateway (MikroTik)",
		"assigned_external_port", localResult.ExternalPort,
		"rule_id", localResult.RuleID)

	// Add rollback for local mapping
	tx.AddRollback(func() error {
		slog.Info("Rolling back local port mapping",
			"internal_port", request.InternalPort,
			"external_port", localResult.ExternalPort)
		return s.mikrotik.DeletePortMappingByID(localResult.RuleID)
	})

	// Step 2: Create mapping on VPN gateway
	slog.Info("Sending to VPN gateway",
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

	slog.Info("Received from VPN gateway",
		"assigned_external_port", vpnResult.ExternalPort,
		"granted_lifetime", vpnResult.Lifetime)

	// Add rollback for VPN mapping
	tx.AddRollback(func() error {
		slog.Info("Rolling back VPN port mapping",
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

	slog.Info("Port opened",
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"local_external_port", localResult.ExternalPort,
		"vpn_external_port", vpnResult.ExternalPort,
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
func (s *mapper) handlePortMappingDeletion(request *natpmp.PortMappingRequest, clientIP string) *natpmp.PortMappingResponse {
	key := key{
		ClientIP:     clientIP,
		Protocol:     request.Protocol,
		InternalPort: request.InternalPort,
	}

	// Copy mapping data while holding lock, then delete
	s.mu.Lock()
	existingMapping, exists := s.mappings[key]
	var mappingCopy mapping
	if exists {
		mappingCopy = *existingMapping // Copy before releasing lock
		delete(s.mappings, key)
	}
	s.mu.Unlock() // Note: Using defer here would hold lock during external API calls below

	if exists {
		protocolStr := protocolToString(request.Protocol)

		s.mikrotik.DeletePortMapping(protocolStr, int(request.InternalPort), clientIP)

		// Delete VPN mapping - use copied data
		deleteReq := &natpmp.PortMappingRequest{
			Protocol:                   request.Protocol,
			InternalPort:               mappingCopy.LocalExternalPort,
			SuggestedExternalPort:      0,
			RequestedLifetimeInSeconds: 0,
		}
		s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq)

		slog.Info("Port closed",
			"protocol", protocolName(request.Protocol),
			"internal_port", request.InternalPort)
	}

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
	slog.Info("Client renewal request",
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
		m.Lifetime = vpnResult.Lifetime
		m.ExpiresAt = time.Now().Add(time.Duration(vpnResult.Lifetime) * time.Second)
		m.VpnExternalPort = vpnResult.ExternalPort
	}

	slog.Info("Renewal successful",
		"protocol", protocolName(request.Protocol),
		"internal_port", request.InternalPort,
		"vpn_external_port", vpnResult.ExternalPort,
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

	s.mappings[key] = mapping

	slog.Info("Added mapping to state",
		"client_ip", mapping.ClientIP,
		"protocol", protocolName(mapping.Protocol),
		"internal_port", mapping.InternalPort,
		"local_external_port", mapping.LocalExternalPort,
		"vpn_external_port", mapping.VpnExternalPort,
		"mikrotik_rule_id", mapping.MikroTikRuleID)
}

// ReconcileRules removes MikroTik rules that are not tracked in state
// and cleans up expired mappings
func (s *mapper) ReconcileRules() error {
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
	s.mu.RUnlock() // Note: defer not used to minimize lock hold time during rule iteration

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
func (s *mapper) cleanupExpiredMappings() {
	now := time.Now()

	// First pass: identify expired mappings and copy data we need
	s.mu.Lock()
	type expiredMapping struct {
		key          key
		protocol     natpmp.Protocol
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
	s.mu.Unlock() // Note: defer not used to avoid holding lock during external API calls below

	// Second pass: cleanup external resources without holding lock
	for _, expired := range expiredMappings {
		protocolStr := protocolToString(expired.protocol)

		s.mikrotik.DeletePortMapping(protocolStr, int(expired.internalPort), expired.clientIP)

		// Delete VPN mapping
		deleteReq := &natpmp.PortMappingRequest{
			Protocol:                   expired.protocol,
			InternalPort:               expired.localExtPort,
			SuggestedExternalPort:      0,
			RequestedLifetimeInSeconds: 0,
		}
		s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq)

		slog.Info("Cleaned up expired mapping",
			"protocol", protocolName(expired.protocol),
			"internal_port", expired.internalPort)
	}

	if len(expiredMappings) > 0 {
		slog.Info("Expired mappings cleaned up", "count", len(expiredMappings))
	}
}

// DeleteAll removes all mappings (called on shutdown)
func (s *mapper) DeleteAll() error {
	// Copy all mappings while holding lock
	s.mu.Lock()
	mappingsToDelete := make([]*mapping, 0, len(s.mappings))
	for _, mapping := range s.mappings {
		mappingCopy := *mapping
		mappingsToDelete = append(mappingsToDelete, &mappingCopy)
	}
	// Clear the map
	s.mappings = make(map[key]*mapping)
	s.mu.Unlock() // Note: defer not used to avoid holding lock during external API calls below

	slog.Info("Deleting all mappings", "count", len(mappingsToDelete))

	// Delete external resources without holding lock
	for _, mapping := range mappingsToDelete {
		protocolStr := protocolToString(mapping.Protocol)

		if err := s.mikrotik.DeletePortMapping(protocolStr, int(mapping.InternalPort), mapping.ClientIP.String()); err != nil {
			slog.Error("Failed to delete local mapping", "error", err)
		}

		// Delete VPN mapping
		deleteReq := &natpmp.PortMappingRequest{
			Protocol:                   mapping.Protocol,
			InternalPort:               mapping.LocalExternalPort,
			SuggestedExternalPort:      0,
			RequestedLifetimeInSeconds: 0,
		}
		if _, err := s.vpnGatewayNATClient.SendPortMappingRequest(deleteReq); err != nil {
			slog.Error("Failed to delete VPN mapping", "error", err)
		}
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

// Get retrieves a mapping (for debugging/inspection)
func (s *mapper) get(clientIP net.IP, protocol natpmp.Protocol, internalPort uint16) (*mapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := key{
		ClientIP:     clientIP.String(),
		Protocol:     protocol,
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
