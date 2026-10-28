package logger

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jaewoook/server-monitor/internal/config"
)

func TestRotatingFile_BasicWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	rf, err := NewRotatingFile(logPath, 1024, 3)
	if err != nil {
		t.Fatalf("unexpected error creating RotatingFile: %v", err)
	}
	defer rf.Close()

	msg := "hello server-monitor log\n"
	n, err := rf.Write([]byte(msg))
	if err != nil {
		t.Fatalf("unexpected error writing to file: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if string(content) != msg {
		t.Errorf("expected %q, got %q", msg, string(content))
	}
}

func TestRotatingFile_CreateNestedDirectory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nested", "sub", "test.log")

	rf, err := NewRotatingFile(logPath, 1024, 3)
	if err != nil {
		t.Fatalf("unexpected error creating RotatingFile with nested dir: %v", err)
	}
	defer rf.Close()

	if _, err := rf.Write([]byte("nested log\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("expected log file to exist at %s: %v", logPath, err)
	}
}

func TestRotatingFile_RotationAndMaxBackups(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")

	// Limit to 50 bytes, max 3 backups (.1, .2, .3)
	rf, err := NewRotatingFile(logPath, 50, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rf.Close()

	// Write 1: 30 bytes
	chunk1 := "111111111122222222223333333333" // 30 bytes
	if _, err := rf.Write([]byte(chunk1)); err != nil {
		t.Fatal(err)
	}
	// No rotation yet
	if _, err := os.Stat(logPath + ".1"); !os.IsNotExist(err) {
		t.Errorf("expected app.log.1 not to exist yet")
	}

	// Write 2: 30 bytes (total would be 60 > 50 -> rotate)
	chunk2 := "444444444455555555556666666666" // 30 bytes
	if _, err := rf.Write([]byte(chunk2)); err != nil {
		t.Fatal(err)
	}

	// app.log.1 should have chunk1, app.log should have chunk2
	c1, _ := os.ReadFile(logPath + ".1")
	if string(c1) != chunk1 {
		t.Errorf("expected app.log.1 to contain chunk1, got %q", string(c1))
	}
	cur, _ := os.ReadFile(logPath)
	if string(cur) != chunk2 {
		t.Errorf("expected app.log to contain chunk2, got %q", string(cur))
	}

	// Write 3: 30 bytes -> rotate again
	chunk3 := "777777777788888888889999999999" // 30 bytes
	if _, err := rf.Write([]byte(chunk3)); err != nil {
		t.Fatal(err)
	}
	// Now app.log.2 = chunk1, app.log.1 = chunk2, app.log = chunk3
	c2, _ := os.ReadFile(logPath + ".2")
	if string(c2) != chunk1 {
		t.Errorf("expected app.log.2 to contain chunk1, got %q", string(c2))
	}

	// Write 4: 30 bytes -> rotate again
	chunk4 := "AAAAAAAAAABBBBBBBBBBCCCCCCCCCC" // 30 bytes
	if _, err := rf.Write([]byte(chunk4)); err != nil {
		t.Fatal(err)
	}
	// Now app.log.3 = chunk1, app.log.2 = chunk2, app.log.1 = chunk3, app.log = chunk4
	c3, _ := os.ReadFile(logPath + ".3")
	if string(c3) != chunk1 {
		t.Errorf("expected app.log.3 to contain chunk1, got %q", string(c3))
	}

	// Write 5: 30 bytes -> rotate again. Max backups = 3, so chunk1 (.3) is discarded!
	chunk5 := "DDDDDDDDDDEEEEEEEEEEFFFFFFFFFF" // 30 bytes
	if _, err := rf.Write([]byte(chunk5)); err != nil {
		t.Fatal(err)
	}
	// app.log.3 should now be chunk2, app.log.4 should NOT exist
	c3New, _ := os.ReadFile(logPath + ".3")
	if string(c3New) != chunk2 {
		t.Errorf("expected app.log.3 to contain chunk2 after eviction, got %q", string(c3New))
	}
	if _, err := os.Stat(logPath + ".4"); !os.IsNotExist(err) {
		t.Errorf("expected app.log.4 to NOT exist (max_backups=3)")
	}
}

func TestRotatingFile_ResumeExistingSize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "resume.log")

	// Pre-create file with 40 bytes
	initialData := strings.Repeat("A", 40)
	if err := os.WriteFile(logPath, []byte(initialData), 0644); err != nil {
		t.Fatal(err)
	}

	// Open with limit 50 bytes
	rf, err := NewRotatingFile(logPath, 50, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rf.Close()

	// Writing 20 bytes should trigger rotation because 40 + 20 > 50
	newData := strings.Repeat("B", 20)
	if _, err := rf.Write([]byte(newData)); err != nil {
		t.Fatal(err)
	}

	b1, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatalf("failed reading rotated file: %v", err)
	}
	if string(b1) != initialData {
		t.Errorf("expected rotated file to have initialData, got %q", string(b1))
	}

	cur, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed reading active file: %v", err)
	}
	if string(cur) != newData {
		t.Errorf("expected active file to have newData, got %q", string(cur))
	}
}

func TestRotatingFile_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "concurrent.log")

	rf, err := NewRotatingFile(logPath, 200, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()

	var wg sync.WaitGroup
	workers := 10
	linesPerWorker := 20
	line := "concurrency test log line\n"

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < linesPerWorker; j++ {
				if _, err := rf.Write([]byte(line)); err != nil {
					t.Errorf("concurrent write error: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSetupAndReset(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "setup.log")
	var consoleBuf bytes.Buffer

	cfg := &config.LoggingConfig{
		Enabled:    true,
		FilePath:   logPath,
		MaxSizeMB:  1,
		MaxBackups: 2,
		Console:    true,
	}

	closer, err := Setup(cfg, &consoleBuf)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer func() {
		Reset()
		if closer != nil {
			closer.Close()
		}
	}()

	testLogMsg := "test log message via standard logger"
	log.Println(testLogMsg)

	// Verify it wrote to console buffer
	if !strings.Contains(consoleBuf.String(), testLogMsg) {
		t.Errorf("expected consoleBuf to contain %q, got %q", testLogMsg, consoleBuf.String())
	}

	// Verify it wrote to log file
	fileContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(fileContent), testLogMsg) {
		t.Errorf("expected fileContent to contain %q, got %q", testLogMsg, string(fileContent))
	}

	// Reset standard log
	Reset()
	if closer != nil {
		closer.Close()
	}

	// Logging after Reset should not write to consoleBuf
	consoleBuf.Reset()
	log.Println("after reset message")
	if consoleBuf.Len() > 0 {
		t.Errorf("expected empty consoleBuf after reset, got %q", consoleBuf.String())
	}
}

func TestSetup_Disabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "disabled.log")

	cfg := &config.LoggingConfig{
		Enabled:  false,
		FilePath: logPath,
	}

	closer, err := Setup(cfg)
	if err != nil {
		t.Fatalf("unexpected error when disabled: %v", err)
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			t.Errorf("unexpected error closing noop closer: %v", err)
		}
	}

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("expected file not to be created when logging disabled")
	}
}
