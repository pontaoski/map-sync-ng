package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	MainConfig      MainConfig
	WhitelistConfig WhitelistConfig
}

type MainConfig struct {
	WhitelistEnabled         bool   `json:"whitelist"`
	ServerAddressMustInclude string `json:"server"`
}

type WhitelistConfig []string

func LoadConfig() (*Config, error) {
	c := &Config{}

	maindata, err := os.ReadFile("config.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open main config file: %w", err)
	}

	whitelistdata, err := os.ReadFile("whitelist.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open whitelist config file: %w", err)
	}

	err = json.Unmarshal(maindata, &c.MainConfig)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(whitelistdata, &c.WhitelistConfig)
	if err != nil {
		return nil, err
	}

	return c, nil
}
