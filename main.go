package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/features-not-bugs/mikrotik-double-natpmp/config"
	"github.com/features-not-bugs/mikrotik-double-natpmp/mikrotik"
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

	// Start periodic reconciliation (every 1 minute)
	go func() {
		ticker := time.NewTicker(time.Minute)
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

	// Stop NAT-PMP server
	slog.Info("Stopping NAT-PMP server...")
	if err := mapper.Stop(); err != nil {
		slog.Error("failed to stop NAT-PMP server", "error", err)
	}

	// Delete all port mappings
	slog.Info("Deleting all port mappings...")

	done := make(chan struct{})
	go func() {
		if err := mapper.DeleteAll(); err != nil {
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
