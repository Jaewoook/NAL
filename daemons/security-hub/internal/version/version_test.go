package version

import (
	"runtime/debug"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	if got := resolve("2026-11-27.16.17", nil); got != "2026-11-27.16.17" {
		t.Fatalf("expected stamped version, got %q", got)
	}

	vcsTime := time.Date(2026, 11, 27, 7, 15, 0, 0, time.UTC)
	expected := vcsTime.Local().Format(versionTimeLayout)
	got := resolve("", func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Settings: []debug.BuildSetting{
				{Key: "vcs.time", Value: vcsTime.Format(time.RFC3339)},
			},
		}, true
	})
	if got != expected {
		t.Fatalf("expected VCS fallback %q, got %q", expected, got)
	}

	if got := resolve("", func() (*debug.BuildInfo, bool) { return nil, false }); got != "dev" {
		t.Fatalf("expected dev fallback, got %q", got)
	}
}
