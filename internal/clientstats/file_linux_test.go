//go:build linux

package clientstats

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxPrivateFileBoundary(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "writable_file", "hardlink", "wrong_owner", "writable_dir", "parent_symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "clients.json")
			target := filepath.Join(directory, "protected")
			switch kind {
			case "symlink":
				os.WriteFile(target, []byte("sentinel"), 0640)
				os.Symlink(target, path)
			case "fifo":
				unix.Mkfifo(path, 0640)
			case "writable_file":
				os.WriteFile(path, []byte("sentinel"), 0640)
				os.Chmod(path, 0660)
			case "hardlink":
				os.WriteFile(target, []byte("sentinel"), 0640)
				os.Link(target, path)
			case "wrong_owner":
				if os.Geteuid() != 0 {
					t.Skip("requires isolated root fixture")
				}
				os.WriteFile(path, []byte("sentinel"), 0640)
				os.Chown(path, 12345, 12345)
			case "writable_dir":
				os.Chmod(directory, 0777)
			case "parent_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				os.Symlink(directory, alias)
				path = filepath.Join(alias, "clients.json")
			}
			collector, err := New(path)
			if err == nil {
				collector.Close()
				t.Fatal("unsafe file boundary accepted")
			}
			if strings.Contains(err.Error(), directory) {
				t.Fatal("failure disclosed input path")
			}
			if data, e := os.ReadFile(target); e == nil && string(data) != "sentinel" {
				t.Fatal("protected target changed")
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
		other.Close()
		t.Fatal("second writer accepted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := New(path)
	if err != nil {
		t.Fatal("writer lock not released")
	}
	again.Close()
}
