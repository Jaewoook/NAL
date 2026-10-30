package scanner

import (
	"context"
	"os"
	"os/exec"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OSCommandRunner struct{}

func NewOSCommandRunner() *OSCommandRunner {
	return &OSCommandRunner{}
}

func (r *OSCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	return cmd.CombinedOutput()
}
