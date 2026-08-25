package version

import "runtime"

// Version — семантическая версия или git-описание сборки.
var Version = "dev"

// BuildDate — дата сборки в UTC (RFC3339), подставляется линкером.
var BuildDate = "unknown"

// Info содержит сведения о текущем бинарнике.
type Info struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Current возвращает сведения о собранном бинарнике.
func Current() Info {
	return Info{
		Version:   Version,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String возвращает краткую строку для CLI (`gophkeeper version`).
func String() string {
	return Version + " (" + BuildDate + ")"
}
