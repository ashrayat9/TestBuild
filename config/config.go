package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GoProxies     []string `yaml:"gomodule-proxies,omitempty"`
	GitRepos      []string `yaml:"git-repos,omitempty"`
	MavenRepos    []string `yaml:"maven-repos,omitempty"`
	NpmRepos      []string `yaml:"npm-repos,omitempty"`
	PypiRepos     []string `yaml:"pypi-repos,omitempty"`
	ComposerRepos []string `yaml:"composer-repos,omitempty"`
	AlpineRepos   []string `yaml:"alpine-repos,omitempty"`
	RubygemsRepos []string `yaml:"rubygems-repos,omitempty"`
	NugetRepos    []string `yaml:"nuget-repos,omitempty"`
}

var (
	cfg = &Config{}
)

func Parse(file string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf(`error opening configuration file: %w`, err)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file: %w", err)
	}
	cfg := &Config{}
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("error decoding configuration file: %w", err)
	}
	return cfg, nil
}

func Set(file string) error {
	var err error
	cfg, err = Parse(file)
	if err != nil {
		return err
	}

	return nil
}

func Cfg() *Config {
	return cfg
}
