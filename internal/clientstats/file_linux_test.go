//go:build linux

package clientstats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxPrivateFileBoundary(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "writable_file", "hardlink", "wrong_owner", "writable_dir", "parent_symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "clients.json")
			target := filepath.Join(directory, "protected")
			switch kind {
			case "symlink":
				if err := os.WriteFile(target, []byte("sentinel"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "writable_file":
				if err := os.WriteFile(path, []byte("sentinel"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(target, []byte("sentinel"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			case "wrong_owner":
				if os.Geteuid() != 0 {
					t.Skip("requires isolated root fixture")
				}
				if err := os.WriteFile(path, []byte("sentinel"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 12345, 12345); err != nil {
					t.Fatal(err)
				}
			case "writable_dir":
				if err := os.Chmod(directory, 0777); err != nil {
					t.Fatal(err)
				}
			case "parent_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(directory, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "clients.json")
			}
			collector, err := New(path)
			if err == nil {
				if closeErr := collector.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				t.Fatal("unsafe file boundary accepted")
			}
			if strings.Contains(err.Error(), directory) {
				t.Fatal("failure disclosed input path")
			}
			if kind == "symlink" || kind == "hardlink" {
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "sentinel" {
					t.Fatal("protected target changed")
				}
			}
		})
	}
}

func TestLinuxCheckpointModeAndSingleWriter(t *testing.T) {
	c, path := newTestCollector(t)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("checkpoint permissions invalid")
	}
	if other, err := New(path); err == nil {
		if closeErr := other.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("second writer accepted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := New(path)
	if err != nil {
		t.Fatal("writer lock not released")
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}
