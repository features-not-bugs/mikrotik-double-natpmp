package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mapping"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
	"github.com/features-not-bugs/mikrotik-double-natpmp/natpmp"
)

func main() {
	// Configure logging level from environment variable
	logLevel := slog.LevelInfo // default
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		switch strings.ToUpper(level) {
		case "DEBUG":
			logLevel = slog.LevelDebug
		case "INFO":
			logLevel = slog.LevelInfo
		case "WARN":
			logLevel = slog.LevelWarn
		case "ERROR":
			logLevel = slog.LevelError
		}
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	handler := slog.NewTextHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(handler))

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("Starting double-natpmp service",
		"mikrotik_api", cfg.LocalAPIAddress,
		"mikrotik_in_interface", cfg.LocalInInterface,
		"vpn_gateway", cfg.VpnGateway.String(),
		"listen_addr", cfg.ListenAddr)

	// Create MikroTik API client for local router
	mikroTikClient, err := mikrotik.NewClient(cfg)
	if err != nil {
		slog.Error("failed to connect to MikroTik API", "error", err)
		os.Exit(1)
	}
	defer mikroTikClient.Close()

	// Auto-detect interface if not configured
	if cfg.LocalInInterface == "" {
		slog.Info("Auto-detecting interface for VPN gateway", "gateway", cfg.VpnGateway.String())
		detectedInterface, err := mikroTikClient.GetInterfaceForGateway(cfg.VpnGateway.String())
		if err != nil {
			slog.Warn("Failed to auto-detect interface, using 'bridge' as default", "error", err)
			cfg.LocalInInterface = "bridge"
		} else {
			cfg.LocalInInterface = detectedInterface
			slog.Info("Auto-detected interface", "interface", detectedInterface)
		}
	}

	// Create mapping service
	mappingService := mapping.NewService(cfg, mikroTikClient)

	// Reconcile existing MikroTik rules on startup
	if err := mappingService.ReconcileRules(); err != nil {
		slog.Error("failed to reconcile rules", "error", err)
		// Don't exit, continue with service start
	}

	// Create NAT-PMP server
	server := natpmp.NewServer(cfg.ListenAddr)

	// Register PUBLIC_ADDRESS handler - forwards to VPN gateway
	server.OnPublicAddress(func(req *natpmp.Request, clientAddr net.IP) ([]byte, error) {
		slog.Debug("Handling PUBLIC_ADDRESS request", "from", clientAddr)

		// Create PUBLIC_ADDRESS request (2 bytes: version 0, opcode 0)
		request := make([]byte, 2)
		request[0] = natpmp.VersionNATPMP
		request[1] = natpmp.OpcodePublicAddress

		// Forward to VPN gateway
		return natpmp.ForwardRequest(request, cfg.VpnGateway, 10*time.Second)
	})

	// Register MAP_UDP handler
	server.OnMapUDP(func(req *natpmp.Request, clientAddr net.IP) ([]byte, error) {
		protocol := "udp"

		// Handle deletion (lifetime = 0)
		if req.Lifetime == 0 {
			slog.Debug("Port mapping deletion request",
				"from", clientAddr.String(),
				"protocol", "UDP",
				"internal_port", req.InternalPort)
			err := mappingService.Delete(clientAddr, protocol, req.InternalPort)
			if err != nil {
				slog.Debug("Mapping not found for deletion (OK - idempotent)", "error", err, "port", req.InternalPort)
				// Deletion is idempotent - success even if mapping doesn't exist
			}
			// Always return success for deletion (RFC 6886 - idempotent operation)
			resp := natpmp.CreateSuccessResponse(natpmp.OpcodeMapUDP, req.InternalPort, 0, 0)
			slog.Debug("Sending deletion success response", "port", req.InternalPort, "protocol", "UDP", "response_hex", fmt.Sprintf("%x", resp))
			return resp, nil
		}

		// Log creation requests
		slog.Info("Port forward request received",
			"from", clientAddr.String(),
			"protocol", "UDP",
			"internal_port", req.InternalPort,
			"suggested_external_port", req.SuggestedExtPort,
			"lifetime", req.Lifetime)

		// Create mapping
		err := mappingService.Create(clientAddr, protocol, req.InternalPort, req.SuggestedExtPort, req.Lifetime)
		if err != nil {
			return nil, err
		}

		// Get the mapping to retrieve actual external port
		m, err := mappingService.Get(clientAddr, protocol, req.InternalPort)
		if err != nil {
			return nil, err
		}

		return natpmp.CreateSuccessResponse(natpmp.OpcodeMapUDP, req.InternalPort, m.VpnExternalPort, m.Lifetime), nil
	})

	// Register MAP_TCP handler
	server.OnMapTCP(func(req *natpmp.Request, clientAddr net.IP) ([]byte, error) {
		protocol := "tcp"

		// Handle deletion (lifetime = 0)
		if req.Lifetime == 0 {
			slog.Debug("Port mapping deletion request",
				"from", clientAddr.String(),
				"protocol", "TCP",
				"internal_port", req.InternalPort)
			err := mappingService.Delete(clientAddr, protocol, req.InternalPort)
			if err != nil {
				slog.Debug("Mapping not found for deletion (OK - idempotent)", "error", err, "port", req.InternalPort)
				// Deletion is idempotent - success even if mapping doesn't exist
			}
			// Always return success for deletion (RFC 6886 - idempotent operation)
			resp := natpmp.CreateSuccessResponse(natpmp.OpcodeMapTCP, req.InternalPort, 0, 0)
			slog.Debug("Sending deletion success response", "port", req.InternalPort, "protocol", "TCP", "response_hex", fmt.Sprintf("%x", resp))
			return resp, nil
		}

		// Log creation requests
		slog.Info("Port forward request received",
			"from", clientAddr.String(),
			"protocol", "TCP",
			"internal_port", req.InternalPort,
			"suggested_external_port", req.SuggestedExtPort,
			"lifetime", req.Lifetime)

		// Create mapping
		err := mappingService.Create(clientAddr, protocol, req.InternalPort, req.SuggestedExtPort, req.Lifetime)
		if err != nil {
			return nil, err
		}

		// Get the mapping to retrieve actual external port
		m, err := mappingService.Get(clientAddr, protocol, req.InternalPort)
		if err != nil {
			return nil, err
		}

		return natpmp.CreateSuccessResponse(natpmp.OpcodeMapTCP, req.InternalPort, m.VpnExternalPort, m.Lifetime), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx); err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	// Start periodic reconciliation (every 1 minute)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := mappingService.ReconcileRules(); err != nil {
					slog.Error("reconciliation failed", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	slog.Info("Shutdown signal received, cleaning up...")

	// Cancel context to stop server
	cancel()

	// Stop server
	if err := server.Stop(); err != nil {
		slog.Error("failed to stop server", "error", err)
	}

	// Delete all port mappings
	slog.Info("Deleting all port mappings...")

	done := make(chan struct{})
	go func() {
		if err := mappingService.DeleteAll(); err != nil {
			slog.Error("failed to delete all mappings", "error", err)
		}
		close(done)
	}()

	// Wait for cleanup with timeout
	select {
	case <-done:
		slog.Info("Cleanup completed successfully")
	case <-time.After(30 * time.Second):
		slog.Warn("Cleanup timed out after 30 seconds")
	}

	slog.Info("Shutdown complete")
}
