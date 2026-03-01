package config

import (
	"os"

	"github.com/getcreddy/creddy/pkg/policy"
	"gopkg.in/yaml.v3"
)

// Config represents the creddy server configuration
type Config struct {
	Policies []policy.Policy `yaml:"policies"`
}

// Load reads config from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
