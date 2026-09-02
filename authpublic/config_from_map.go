package authpublic

import (
	"fmt"

	"github.com/goccy/go-yaml"
)

// ConfigFromMap unmarshals a YAML-shaped map (for example a koanf auth: block)
// into Config. A nil map yields an empty Config.
func ConfigFromMap(m map[string]any) (*Config, error) {
	cfg := &Config{}
	if m == nil {
		return cfg, nil
	}

	data, err := yaml.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("auth config: marshal: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("auth config: unmarshal: %w", err)
	}
	return cfg, nil
}
