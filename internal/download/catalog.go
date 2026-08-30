package download

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gokeeper/pkg/version"
)

// ErrNotFound — бинарник для платформы отсутствует на диске.
var ErrNotFound = errors.New("client binary not found")

// Platform — идентификатор ОС в API скачивания.
type Platform string

// Поддерживаемые платформы CLI.
const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
)

// Binary описывает один собранный клиент.
type Binary struct {
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Filename  string `json:"filename"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	Available bool   `json:"available"`
}

// Catalog читает каталог bin/clients и optional manifest.json.
type Catalog struct {
	Dir string
}

type manifest struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	Binaries  []struct {
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		Filename string `json:"filename"`
	} `json:"binaries"`
}

var defaultBinaries = []Binary{
	{Platform: "windows", Arch: "amd64", Filename: "gophkeeper-windows-amd64.exe"},
	{Platform: "linux", Arch: "amd64", Filename: "gophkeeper-linux-amd64"},
	{Platform: "darwin", Arch: "amd64", Filename: "gophkeeper-darwin-amd64"},
}

// NormalizePlatform приводит macos/win/osx к каноническому ключу.
func NormalizePlatform(p string) (Platform, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "windows", "win", "win64", "windows-amd64":
		return PlatformWindows, nil
	case "linux", "linux64", "linux-amd64":
		return PlatformLinux, nil
	case "darwin", "macos", "mac", "osx", "apple", "darwin-amd64":
		return PlatformDarwin, nil
	default:
		return "", ErrNotFound
	}
}

// List возвращает три платформы и факт наличия файла.
func (c Catalog) List() []Binary {
	ver, date := c.version()
	specs := c.specs()
	out := make([]Binary, 0, len(specs))
	for _, b := range specs {
		b.Version = ver
		b.BuildDate = date
		b.URL = "/api/v1/client/" + b.Platform
		path := filepath.Join(c.Dir, b.Filename)
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			b.Size = st.Size()
			b.Available = true
		}
		out = append(out, b)
	}
	return out
}

// Get возвращает метаданные и путь к файлу для отдачи.
func (c Catalog) Get(platform string) (Binary, string, error) {
	p, err := NormalizePlatform(platform)
	if err != nil {
		return Binary{}, "", err
	}
	for _, b := range c.List() {
		if b.Platform == string(p) {
			if !b.Available {
				return b, "", ErrNotFound
			}
			return b, filepath.Join(c.Dir, b.Filename), nil
		}
	}
	return Binary{}, "", ErrNotFound
}

func (c Catalog) specs() []Binary {
	m, err := c.readManifest()
	if err != nil || len(m.Binaries) == 0 {
		return append([]Binary(nil), defaultBinaries...)
	}
	out := make([]Binary, 0, len(m.Binaries))
	for _, b := range m.Binaries {
		out = append(out, Binary{Platform: b.Platform, Arch: b.Arch, Filename: b.Filename})
	}
	return out
}

func (c Catalog) version() (string, string) {
	if m, err := c.readManifest(); err == nil && m.Version != "" {
		return m.Version, m.BuildDate
	}
	info := version.Current()
	return info.Version, info.BuildDate
}

func (c Catalog) readManifest() (manifest, error) {
	raw, err := os.ReadFile(filepath.Join(c.Dir, "manifest.json"))
	if err != nil {
		return manifest{}, err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return manifest{}, err
	}
	return m, nil
}

// DisplayName — подпись платформы для веб-страницы.
func DisplayName(platform string) string {
	switch platform {
	case "windows":
		return "Windows (x64)"
	case "linux":
		return "Linux (x64)"
	case "darwin":
		return "macOS (x64)"
	default:
		return platform
	}
}
