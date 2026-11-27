//go:build !agent

package web

import "embed"

// HasEmbeddedUI reports whether the web dashboard static assets are embedded in this binary.
const HasEmbeddedUI = true

//go:embed static/*
var staticEmbedFS embed.FS
