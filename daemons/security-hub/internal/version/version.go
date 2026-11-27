package version

import (
	"runtime/debug"
	"strings"
	"time"
)

// BuildVersion is injected at link time via:
// -ldflags "-X github.com/jaewoook/security-hub/internal/version.BuildVersion=YYYY-MM-DD.HH.MM"
var BuildVersion = ""

const versionTimeLayout = "2006-01-02.15.04"

var readBuildInfo = debug.ReadBuildInfo

// Current returns the stamped build version (YYYY-MM-DD.HH.MM), falling back to
// Go's embedded VCS timestamp when built without ldflags, or "dev".
func Current() string {
	return resolve(BuildVersion, readBuildInfo)
}

func resolve(stamped string, infoFn func() (*debug.BuildInfo, bool)) string {
	if v := strings.TrimSpace(stamped); v != "" {
		return v
	}
	if infoFn != nil {
		if info, ok := infoFn(); ok && info != nil {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.time" && setting.Value != "" {
					if ts, err := time.Parse(time.RFC3339, setting.Value); err == nil {
						return ts.Local().Format(versionTimeLayout)
					}
				}
			}
		}
	}
	return "dev"
}
