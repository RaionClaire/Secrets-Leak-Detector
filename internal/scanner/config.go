package scanner

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ExcludeDirs       []string `yaml:"exclude_dirs"`
	MaxFileSizeBytes  int      `yaml:"max_file_size_bytes"`
	EnableEntropy     bool     `yaml:"enable_entropy"`
	EntropyThreshold  float64  `yaml:"entropy_threshold"`
	MinEntropyLen     int      `yaml:"min_entropy_len"`
	AllowlistRegex    string   `yaml:"allowlist_regex"`
}

func defaultConfig() Config {
	return Config{
		ExcludeDirs:      []string{"vendor", "node_modules", ".git", "dist", "build"},
		MaxFileSizeBytes: 1024 * 1024, // 1MB
		EnableEntropy:    true,
		EntropyThreshold: 4.7,
		MinEntropyLen:    24,
		AllowlistRegex:   "",
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	_ = yaml.Unmarshal(b, &cfg)
	return cfg, nil
}
