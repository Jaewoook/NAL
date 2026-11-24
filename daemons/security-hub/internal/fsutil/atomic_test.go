package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic_CreatesAndReplacesWithPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")

	if err := WriteFileAtomic(target, []byte(`{"v":1}`), 0600); err != nil {
		t.Fatalf("WriteFileAtomic initial failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != `{"v":1}` {
		t.Fatalf("unexpected content: %q", string(got))
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected perm 0600, got %04o", info.Mode().Perm())
	}

	if err := WriteFileAtomic(target, []byte(`{"v":2}`), 0644); err != nil {
		t.Fatalf("WriteFileAtomic overwrite failed: %v", err)
	}
	got, _ = os.ReadFile(target)
	if string(got) != `{"v":2}` {
		t.Fatalf("unexpected overwritten content: %q", string(got))
	}
}
