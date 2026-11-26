package scanner

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// StreamingCommandRunner is an optional extension of CommandRunner that emits stdout/stderr
// lines in real time while still returning the combined output bytes on completion.
type StreamingCommandRunner interface {
	RunStreaming(ctx context.Context, onLine func(stream, line string), name string, args ...string) ([]byte, error)
}

type OSCommandRunner struct{}

func NewOSCommandRunner() *OSCommandRunner {
	return &OSCommandRunner{}
}

func commandEnv() []string {
	return append(os.Environ(), "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "DEBIAN_FRONTEND=noninteractive", "LC_MESSAGES=C")
}

func (r *OSCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv()
	return cmd.CombinedOutput()
}

func (r *OSCommandRunner) RunStreaming(ctx context.Context, onLine func(stream, line string), name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var bufMu sync.Mutex
	var combined bytes.Buffer
	var wg sync.WaitGroup

	readStream := func(r io.Reader, streamName string) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			bufMu.Lock()
			combined.WriteString(line)
			combined.WriteByte('\n')
			bufMu.Unlock()
			if onLine != nil && strings.TrimSpace(line) != "" {
				onLine(streamName, line)
			}
		}
	}

	wg.Add(2)
	go readStream(stdoutPipe, "stdout")
	go readStream(stderrPipe, "stderr")

	wg.Wait()
	waitErr := cmd.Wait()
	return combined.Bytes(), waitErr
}
