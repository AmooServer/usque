package supervisor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Diniboy1123/usque/internal/socksauth"
)

func TestAuthenticatedDialRejectsAnonymousFallback(t *testing.T) {
	for _, tc := range []struct {
		mode, password string
		success        bool
	}{
		{"auth", "health-password", true}, {"auth", "wrong-password", false}, {"", "health-password", false}, {"hang", "health-password", false},
	} {
		p, names := localProbe(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "warp=on") }, tc.mode)
		ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
		transport := &http.Transport{TLSClientConfig: p.TLSConfig, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return authenticatedSOCKSDial(ctx, p.Address, network, address, socksauth.Credentials{Username: "health-user", Password: tc.password})
		}}
		client := &http.Client{Transport: transport, Timeout: p.Timeout}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		cancel()
		if resp != nil {
			_ = resp.Body.Close()
		}
		transport.CloseIdleConnections()
		if (err == nil) != tc.success {
			t.Fatal("authenticated dial accepted a wrong password or anonymous fallback")
		}
		if err != nil && strings.Contains(err.Error(), tc.password) {
			t.Fatal("authenticated dial disclosed credentials")
		}
		if tc.success && !strings.HasPrefix(<-names, "example.com:") {
			t.Fatal("authenticated dial did not delegate hostname resolution to SOCKS")
		}
	}
}
