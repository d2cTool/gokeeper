package clientcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config — локальные настройки CLI.
type Config struct {
	Address  string `json:"address"`
	Token    string `json:"token"`
	Insecure bool   `json:"insecure"`
	Path     string `json:"-"`
}

// Load читает ~/.gophkeeper/config.json или возвращает значения по умолчанию.
func Load() (Config, error) {
	path, err := path()
	if err != nil {
		return Config{}, err
	}
	cfg := Config{Address: "localhost:9090", Insecure: true, Path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return Config{}, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	cfg.Path = path
	return cfg, nil
}

// Save атомарно записывает конфиг.
func (c Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

func path() (string, error) {
	if p := os.Getenv("GOPHKEEPER_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gophkeeper", "config.json"), nil
}
