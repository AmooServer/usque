package socksauth

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func authFile(t *testing.T) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root is required to test root-owned SOCKS credential files")
	}
	g, err := user.LookupGroup("usque")
	if err != nil {
		t.Skip("the usque group is required for credential-file ownership tests")
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"username":"test-user","password":"test-password"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		t.Fatal(err)
	}
	return path, gid
}

func TestLoadPrivateCredentials(t *testing.T) {
	path, _ := authFile(t)
	c, err := Load(path)
	if err != nil || c.Username != "test-user" || c.Password != "test-password" {
		t.Fatal("valid root:usque 0640 credentials were not loaded")
	}
}

func TestLoadRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"public-mode", "writable-group", "wrong-owner", "wrong-group", "symlink", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			path, gid := authFile(t)
			switch kind {
			case "public-mode":
				_ = os.Chmod(path, 0644)
			case "writable-group":
				_ = os.Chmod(path, 0660)
			case "wrong-owner":
				_ = os.Chown(path, 12345, gid)
			case "wrong-group":
				_ = os.Chown(path, 0, gid+1)
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "directory":
				path = filepath.Dir(path)
			case "oversized":
				if err := os.WriteFile(path, make([]byte, 4097), 0640); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Load(path); err == nil {
				t.Fatal("unsafe credential file accepted")
			}
		})
	}
}
