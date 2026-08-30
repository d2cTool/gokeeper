package web

import "embed"

// Static — CSS и прочие файлы веб-интерфейса.
//
//go:embed static/*
var Static embed.FS
