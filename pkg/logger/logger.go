// Package logger provides a centralized logging interface for creddy.
// It wraps hashicorp/hclog for consistency with the plugin system.
package logger

import (
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
)

var (
	defaultLogger hclog.Logger
	mu            sync.RWMutex
	debugEnabled  bool
)

func init() {
	// Initialize with a default logger (INFO level, no debug)
	defaultLogger = hclog.New(&hclog.LoggerOptions{
		Name:   "creddy",
		Level:  hclog.Info,
		Output: os.Stderr,
	})
}

// Init initializes the global logger with the specified debug setting.
// Should be called once at startup from the CLI.
func Init(debug bool) {
	mu.Lock()
	defer mu.Unlock()

	debugEnabled = debug

	level := hclog.Info
	if debug {
		level = hclog.Debug
	}

	defaultLogger = hclog.New(&hclog.LoggerOptions{
		Name:   "creddy",
		Level:  level,
		Output: os.Stderr,
	})
}

// IsDebug returns true if debug logging is enabled
func IsDebug() bool {
	mu.RLock()
	defer mu.RUnlock()
	return debugEnabled
}

// Get returns the global logger
func Get() hclog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger
}

// Named returns a named sub-logger
func Named(name string) hclog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger.Named(name)
}

// Debug logs a debug message (only shown when --debug is enabled)
func Debug(msg string, args ...interface{}) {
	mu.RLock()
	defer mu.RUnlock()
	defaultLogger.Debug(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...interface{}) {
	mu.RLock()
	defer mu.RUnlock()
	defaultLogger.Info(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...interface{}) {
	mu.RLock()
	defer mu.RUnlock()
	defaultLogger.Warn(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...interface{}) {
	mu.RLock()
	defer mu.RUnlock()
	defaultLogger.Error(msg, args...)
}

// GetLevel returns the current log level
func GetLevel() hclog.Level {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger.GetLevel()
}

// ForPlugin returns an hclog.Logger suitable for passing to the plugin system.
// This ensures plugins inherit the same log level as creddy.
func ForPlugin() hclog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger.Named("plugin")
}
