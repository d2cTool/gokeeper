package clientcfg_test

import (
	"path/filepath"
	"testing"

	"gokeeper/internal/clientcfg"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	t.Setenv("GOPHKEEPER_CONFIG", path)
	cfg, err := clientcfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address == "" {
		t.Fatal("default address")
	}
	cfg.Token = "abc"
	cfg.Address = "example:9090"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := clientcfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "abc" || got.Address != "example:9090" {
		t.Fatalf("%+v", got)
	}
}

func TestLoadMissingUsesDefaults(t *testing.T) {
	t.Setenv("GOPHKEEPER_CONFIG", filepath.Join(t.TempDir(), "missing", "cfg.json"))
	cfg, err := clientcfg.Load()
	if err != nil || cfg.Address != "localhost:9090" || !cfg.Insecure {
		t.Fatalf("%+v %v", cfg, err)
	}
}
