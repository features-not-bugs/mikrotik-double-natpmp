package utility

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var configureOnce sync.Once

func GetLogger() *slog.Logger {
	configureOnce.Do(func() {
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
	})

	return slog.Default()
}
