//go:build agent

package web

import "embed"

// staticEmbedFS is intentionally empty in agent-only builds (`-tags agent`),
// allowing remote agent binaries to compile without building frontend assets.
var staticEmbedFS embed.FS
