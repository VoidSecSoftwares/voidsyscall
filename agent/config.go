package agent

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	AgentID    []byte   `json:"id"`
	Key        []byte   `json:"key"`
	Channels   []string `json:"channels"`
	ServerAddr string   `json:"server"`
	BeaconPath string   `json:"path"`
	JitterMin  int      `json:"jitter_min"`
	JitterMax  int      `json:"jitter_max"`
	Sleep      int      `json:"sleep"`
	UserAgent  string   `json:"ua"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(cfg.AgentID) == 0 {
		cfg.AgentID = make([]byte, 16)
		for i := range cfg.AgentID {
			cfg.AgentID[i] = byte(i)
		}
	}
	if len(cfg.Key) == 0 {
		cfg.Key = make([]byte, 32)
	}
	if cfg.JitterMin == 0 {
		cfg.JitterMin = 5
	}
	if cfg.JitterMax == 0 {
		cfg.JitterMax = 30
	}
	if cfg.Sleep == 0 {
		cfg.Sleep = 30
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
