//go:build !agent

package web

import "embed"

//go:embed static/*
var staticEmbedFS embed.FS
