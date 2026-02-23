// Package plugin handles loading and managing Creddy plugins.
package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

// Loader manages plugin lifecycle
type Loader struct {
	pluginDir string
	plugins   map[string]*LoadedPlugin
	mu        sync.RWMutex
	logger    hclog.Logger
	watcher   *fsnotify.Watcher
	stopCh    chan struct{}
}

// LoadedPlugin represents a loaded and running plugin
type LoadedPlugin struct {
	Info   *sdk.PluginInfo
	Client *plugin.Client
	Plugin sdk.Plugin
}

// NewLoader creates a new plugin loader
func NewLoader(pluginDir string) *Loader {
	if pluginDir == "" {
		home, _ := os.UserHomeDir()
		pluginDir = filepath.Join(home, ".creddy", "plugins")
	}

	return &Loader{
		pluginDir: pluginDir,
		plugins:   make(map[string]*LoadedPlugin),
		logger:    hclog.NewNullLogger(),
	}
}

// SetLogger sets the logger for plugin communication
func (l *Loader) SetLogger(logger hclog.Logger) {
	l.logger = logger
}

// DiscoverPlugins finds all plugins in the plugin directory
func (l *Loader) DiscoverPlugins() ([]string, error) {
	entries, err := os.ReadDir(l.pluginDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin directory: %w", err)
	}

	var plugins []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Plugin binaries are named creddy-<name> or just the name
		if strings.HasPrefix(name, "creddy-") {
			plugins = append(plugins, strings.TrimPrefix(name, "creddy-"))
		} else {
			plugins = append(plugins, name)
		}
	}

	return plugins, nil
}

// LoadPlugin loads and starts a single plugin
func (l *Loader) LoadPlugin(name string) (*LoadedPlugin, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if already loaded
	if p, ok := l.plugins[name]; ok {
		return p, nil
	}

	// Find the plugin binary
	binaryPath := l.findPluginBinary(name)
	if binaryPath == "" {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}

	// Start the plugin process
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: sdk.HandshakeConfig,
		Plugins:         sdk.PluginMap,
		Cmd:             exec.Command(binaryPath),
		Logger:          l.logger,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
	})

	// Connect via gRPC
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to connect to plugin: %w", err)
	}

	// Get the plugin interface
	raw, err := rpcClient.Dispense("credential")
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to dispense plugin: %w", err)
	}

	p, ok := raw.(sdk.Plugin)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("plugin does not implement Plugin interface")
	}

	// Get plugin info
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := p.Info(ctx)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to get plugin info: %w", err)
	}

	loaded := &LoadedPlugin{
		Info:   info,
		Client: client,
		Plugin: p,
	}

	l.plugins[name] = loaded
	return loaded, nil
}

// LoadAllPlugins discovers and loads all available plugins
func (l *Loader) LoadAllPlugins() error {
	plugins, err := l.DiscoverPlugins()
	if err != nil {
		return err
	}

	for _, name := range plugins {
		if _, err := l.LoadPlugin(name); err != nil {
			l.logger.Warn("failed to load plugin", "name", name, "error", err)
		}
	}

	return nil
}

// GetPlugin returns a loaded plugin by name
func (l *Loader) GetPlugin(name string) (*LoadedPlugin, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	p, ok := l.plugins[name]
	return p, ok
}

// ListPlugins returns all loaded plugins
func (l *Loader) ListPlugins() []*LoadedPlugin {
	l.mu.RLock()
	defer l.mu.RUnlock()

	plugins := make([]*LoadedPlugin, 0, len(l.plugins))
	for _, p := range l.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// UnloadPlugin stops and removes a plugin
func (l *Loader) UnloadPlugin(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	p, ok := l.plugins[name]
	if !ok {
		return fmt.Errorf("plugin not loaded: %s", name)
	}

	p.Client.Kill()
	delete(l.plugins, name)
	return nil
}

// UnloadAll stops all plugins
func (l *Loader) UnloadAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for name, p := range l.plugins {
		p.Client.Kill()
		delete(l.plugins, name)
	}
}

// findPluginBinary looks for the plugin binary in the plugin directory
func (l *Loader) findPluginBinary(name string) string {
	// Try different naming conventions
	candidates := []string{
		filepath.Join(l.pluginDir, "creddy-"+name),
		filepath.Join(l.pluginDir, name),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// PluginDir returns the plugin directory path
func (l *Loader) PluginDir() string {
	return l.pluginDir
}

// Watch starts watching the plugin directory for changes.
// New plugins are automatically loaded, removed plugins are unloaded.
// This method blocks until StopWatch is called or an error occurs.
func (l *Loader) Watch() error {
	// Ensure plugin directory exists
	if err := os.MkdirAll(l.pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	l.mu.Lock()
	l.watcher = watcher
	l.stopCh = make(chan struct{})
	l.mu.Unlock()

	if err := watcher.Add(l.pluginDir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch plugin directory: %w", err)
	}

	l.logger.Info("watching plugin directory for changes", "dir", l.pluginDir)

	for {
		select {
		case <-l.stopCh:
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			l.handleFsEvent(event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			l.logger.Error("watcher error", "error", err)
		}
	}
}

// handleFsEvent processes filesystem events for plugin hot-reload
func (l *Loader) handleFsEvent(event fsnotify.Event) {
	// Extract plugin name from path
	filename := filepath.Base(event.Name)
	name := strings.TrimPrefix(filename, "creddy-")

	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		// New file created - try to load it as a plugin
		// Wait a moment for the file to be fully written
		time.Sleep(100 * time.Millisecond)
		
		// Check if file is executable
		info, err := os.Stat(event.Name)
		if err != nil {
			return
		}
		if info.Mode()&0111 == 0 {
			// Not executable, skip
			return
		}

		l.logger.Info("detected new plugin", "name", name)
		if _, err := l.LoadPlugin(name); err != nil {
			l.logger.Error("failed to load new plugin", "name", name, "error", err)
		} else {
			l.logger.Info("loaded new plugin", "name", name)
		}

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		// File removed - unload the plugin
		l.mu.RLock()
		_, loaded := l.plugins[name]
		l.mu.RUnlock()

		if loaded {
			l.logger.Info("detected plugin removal", "name", name)
			if err := l.UnloadPlugin(name); err != nil {
				l.logger.Error("failed to unload plugin", "name", name, "error", err)
			} else {
				l.logger.Info("unloaded plugin", "name", name)
			}
		}

	case event.Op&fsnotify.Write == fsnotify.Write:
		// File modified - reload the plugin
		l.mu.RLock()
		_, loaded := l.plugins[name]
		l.mu.RUnlock()

		if loaded {
			l.logger.Info("detected plugin update", "name", name)
			// Unload first, then reload
			if err := l.UnloadPlugin(name); err != nil {
				l.logger.Error("failed to unload plugin for reload", "name", name, "error", err)
				return
			}
			// Wait for process to fully terminate
			time.Sleep(100 * time.Millisecond)
			if _, err := l.LoadPlugin(name); err != nil {
				l.logger.Error("failed to reload plugin", "name", name, "error", err)
			} else {
				l.logger.Info("reloaded plugin", "name", name)
			}
		}
	}
}

// StopWatch stops the filesystem watcher
func (l *Loader) StopWatch() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.stopCh != nil {
		close(l.stopCh)
		l.stopCh = nil
	}
	if l.watcher != nil {
		l.watcher.Close()
		l.watcher = nil
	}
}
