package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`

	Database struct {
		DSN        string `yaml:"dsn"`
		Migrations string `yaml:"migrations"`
	} `yaml:"database"`

	Log struct {
		Level  string `yaml:"level"`
		Output string `yaml:"output"`
	} `yaml:"log"`
}

func Init(path string) (*Config, error) {
	yml, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c := &Config{}
	if err = yaml.Unmarshal(yml, c); err != nil {
		return nil, err
	}

	return c, nil
}