package configs

import (
	"log"
	"os"
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

const defaultPathToResolverSettings = "./resolvers.settings.yaml"

// ResolverSettings represent settings for resolver.
type ResolverSettings map[string]map[string]struct {
	ContractAddress string `yaml:"contractAddress"`
	NetworkURL      string `yaml:"networkURL"`
}

// Config structure represent yaml config for did driver.
type Config struct {
	Server struct {
		Port int    `envconfig:"PORT" default:"8080"`
		Host string `envconfig:"HOST" default:"localhost"`
	}
	Ens struct {
		EthNodeURL string `envconfig:"ETH_NODE_URL"`
		Network    string `envconfig:"ENS_NETWORK"`
		Owner      string `envconfig:"ENS_OWNER"`
	}
}

// ReadConfigFromFile parse config file.
func ReadConfigFromFile() (*Config, error) {
	cfg := &Config{}
	err := envconfig.Process("", cfg)
	return cfg, err
}

// ParseResolversSettings parse yaml file with resolver settings.
func ParseResolversSettings(path string) (ResolverSettings, error) {
	if path == "" {
		path = defaultPathToResolverSettings
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("failed to close setting file:", err)
		}
	}()

	settings := ResolverSettings{}
	if err := yaml.NewDecoder(f).Decode(&settings); err != nil {
		return nil, errors.Errorf("invalid yaml file: %v", settings)
	}

	return settings, nil
}
