//go:build agent

package web

import "embed"

// HasEmbeddedUI is false in agent-only builds (`-tags agent`), which omit the web dashboard assets.
const HasEmbeddedUI = false

// staticEmbedFS is intentionally empty in agent-only builds (`-tags agent`),
// allowing remote agent binaries to compile without building frontend assets.
var staticEmbedFS embed.FS
