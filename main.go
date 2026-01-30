package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
	"github.com/features-not-bugs/mikrotik-double-natpmp/utility"
)

func main() {
	// initialize logger
	_ = utility.GetLogger()

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

	// Create mapper
	mapper := newMapper(cfg, mikroTikClient)

	// Reconcile existing MikroTik rules on startup
	if err := mapper.ReconcileRules(); err != nil {
		slog.Error("failed to reconcile rules", "error", err)
		// Don't exit, continue with service start
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start NAT-PMP server
	if err := mapper.Start(ctx); err != nil {
		slog.Error("failed to start NAT-PMP server", "error", err)
		os.Exit(1)
	}
	slog.Info("NAT-PMP server started", "listen_addr", cfg.ListenAddr)

	// Start periodic reconciliation (every 10 minutes as safety net)
	// This only catches orphaned rules from crashes/network issues
	// Normal expiration is handled by per-mapping timers
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := mapper.ReconcileRules(); err != nil {
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

	// Cancel context to stop background tasks
	cancel()

	// Stop NAT-PMP server and cleanup all mappings (with timeout)
	done := make(chan error, 1)
	go func() {
		done <- mapper.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			slog.Error("shutdown failed", "error", err)
		} else {
			slog.Info("Shutdown completed successfully")
		}
	case <-time.After(30 * time.Second):
		slog.Warn("Shutdown timed out after 30 seconds")
	}

	slog.Info("Shutdown complete")
}
