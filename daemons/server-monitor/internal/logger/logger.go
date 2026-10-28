package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/jaewoook/server-monitor/internal/config"
)

// RotatingFile is an io.WriteCloser that automatically rotates the log file
// when its size exceeds maxBytes, keeping up to maxBackups old log files.
type RotatingFile struct {
	mu          sync.Mutex
	filePath    string
	maxBytes    int64
	maxBackups  int
	file        *os.File
	currentSize int64
}

// NewRotatingFile creates or opens a rotating log file.
func NewRotatingFile(filePath string, maxBytes int64, maxBackups int) (*RotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	if maxBackups <= 0 {
		maxBackups = 3
	}

	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory %q: %w", dir, err)
		}
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", filePath, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to stat log file %q: %w", filePath, err)
	}

	return &RotatingFile{
		filePath:    filePath,
		maxBytes:    maxBytes,
		maxBackups:  maxBackups,
		file:        f,
		currentSize: info.Size(),
	}, nil
}

// Write writes log bytes to the active log file, triggering rotation if needed.
func (rf *RotatingFile) Write(p []byte) (n int, err error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	writeLen := int64(len(p))
	if rf.currentSize+writeLen > rf.maxBytes {
		if err := rf.rotate(); err != nil {
			// If rotation fails, write to the existing file anyway to prevent losing logs
			_, _ = rf.file.Write([]byte(fmt.Sprintf("[logger] rotation error: %v\n", err)))
		}
	}

	if rf.file == nil {
		return 0, fmt.Errorf("log file is not open")
	}

	n, err = rf.file.Write(p)
	rf.currentSize += int64(n)
	return n, err
}

// rotate closes the current file, shifts backup files, and opens a new active file.
func (rf *RotatingFile) rotate() error {
	if rf.file != nil {
		_ = rf.file.Close()
		rf.file = nil
	}

	if rf.maxBackups > 0 {
		// Shift existing backups: e.g. .2 -> .3, .1 -> .2
		for i := rf.maxBackups - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", rf.filePath, i)
			dst := fmt.Sprintf("%s.%d", rf.filePath, i+1)
			if _, err := os.Stat(src); err == nil {
				_ = os.Rename(src, dst)
			}
		}

		// Move active file to .1
		dst1 := fmt.Sprintf("%s.1", rf.filePath)
		_ = os.Rename(rf.filePath, dst1)
	} else {
		// No backups, remove the file
		_ = os.Remove(rf.filePath)
	}

	f, err := os.OpenFile(rf.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open new active log file %q: %w", rf.filePath, err)
	}

	rf.file = f
	rf.currentSize = 0
	return nil
}

// Close closes the active log file.
func (rf *RotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.file != nil {
		err := rf.file.Close()
		rf.file = nil
		return err
	}
	return nil
}

type noopCloser struct{}

func (n *noopCloser) Close() error {
	return nil
}

// Setup configures standard library log to route to the rotating file and optionally console.
func Setup(cfg *config.LoggingConfig, consoleWriter ...io.Writer) (io.Closer, error) {
	if cfg == nil || !cfg.Enabled {
		return &noopCloser{}, nil
	}

	var console io.Writer = os.Stdout
	if len(consoleWriter) > 0 && consoleWriter[0] != nil {
		console = consoleWriter[0]
	}

	maxBytes := int64(cfg.MaxSizeMB) * 1024 * 1024
	rf, err := NewRotatingFile(cfg.FilePath, maxBytes, cfg.MaxBackups)
	if err != nil {
		return nil, err
	}

	var out io.Writer = rf
	if cfg.Console {
		out = io.MultiWriter(console, rf)
	}

	log.SetOutput(out)
	log.SetFlags(log.Ldate | log.Ltime)

	return rf, nil
}

// Reset restores standard library log output to os.Stderr and standard flags.
func Reset() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags)
}
