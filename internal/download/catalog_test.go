package download_test

import (
	"os"
	"path/filepath"
	"testing"

	"gokeeper/internal/download"
)

func TestListAndGet(t *testing.T) {
	dir := t.TempDir()
	win := filepath.Join(dir, "gophkeeper-windows-amd64.exe")
	if err := os.WriteFile(win, []byte("mz"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := download.Catalog{Dir: dir}
	list := c.List()
	if len(list) != 3 {
		t.Fatalf("len=%d", len(list))
	}
	var found bool
	for _, b := range list {
		if b.Platform == "windows" && b.Available && b.Size == 2 {
			found = true
		}
		if b.Platform == "linux" && b.Available {
			t.Fatal("linux should be missing")
		}
	}
	if !found {
		t.Fatal("windows binary not listed")
	}
	b, path, err := c.Get("win64")
	if err != nil || path != win || b.Filename == "" {
		t.Fatalf("get: %+v %s %v", b, path, err)
	}
	if _, _, err := c.Get("linux"); err != download.ErrNotFound {
		t.Fatalf("err=%v", err)
	}
	if _, err := download.NormalizePlatform("macos"); err != nil {
		t.Fatal(err)
	}
	if download.DisplayName("darwin") != "macOS (x64)" {
		t.Fatal(download.DisplayName("darwin"))
	}
}
