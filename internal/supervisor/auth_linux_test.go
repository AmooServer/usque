package supervisor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func supervisorAuthFile(t *testing.T, password string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root is required for root-owned credential fixtures")
	}
	g, err := user.LookupGroup("usque")
	if err != nil {
		t.Skip("usque group is required for credential fixtures")
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"username":"health-user","password":"`+password+`"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSupervisorAuthFilePassesPathOnly(t *testing.T) {
	path := supervisorAuthFile(t, "health-password")
	for _, mode := range []string{"socks", "l4-socks"} {
		c, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_SOCKS_AUTH_FILE": path, "USQUE_MODE": mode}[k] })
		if err != nil {
			t.Fatal(err)
		}
		args := c.ChildArgs()
		i := slices.Index(args, "--socks-auth-file")
		if i < 0 || i+1 >= len(args) || args[i+1] != path {
			t.Fatal("credential path missing from child arguments")
		}
		if strings.Contains(strings.Join(args, " "), "health-password") || strings.Contains(strings.Join(args, " "), "health-user") {
			t.Fatal("credentials disclosed in child arguments")
		}
	}
}

func TestAuthenticatedSOCKSHealth(t *testing.T) {
	for _, password := range []string{"health-password", "wrong-password"} {
		probe, _ := localProbe(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "warp=on") }, "auth")
		probe.AuthFile = supervisorAuthFile(t, password)
		_, err := probe.Check(context.Background())
		if (err == nil) != (password == "health-password") {
			t.Fatal("authenticated health result did not match credentials")
		}
		if err != nil && strings.Contains(err.Error(), password) {
			t.Fatal("health error disclosed credentials")
		}
	}
}
