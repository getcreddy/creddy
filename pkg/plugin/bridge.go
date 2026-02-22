package plugin

import (
	"github.com/getcreddy/creddy/pkg/backend"
)

// LoaderBridge implements backend.PluginLoader
type LoaderBridge struct {
	loader *Loader
}

// NewLoaderBridge creates a bridge that implements backend.PluginLoader
func NewLoaderBridge(loader *Loader) *LoaderBridge {
	return &LoaderBridge{loader: loader}
}

// LoadPlugin loads a plugin and returns it as a Backend
func (b *LoaderBridge) LoadPlugin(name string) (backend.Backend, error) {
	p, err := b.loader.LoadPlugin(name)
	if err != nil {
		return nil, err
	}

	return NewPluginBackend(name, p.Plugin), nil
}

// Register sets this loader as the default plugin loader for the backend package
func (b *LoaderBridge) Register() {
	backend.DefaultPluginLoader = b
}
