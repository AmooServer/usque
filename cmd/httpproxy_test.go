package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !authenticate(r, "") {
		t.Fatal("empty expected auth must allow anonymous requests")
	}
	if authenticate(r, "Basic abc") {
		t.Fatal("missing header accepted")
	}
	r.Header.Set("Proxy-Authorization", "Basic abc")
	if !authenticate(r, "Basic abc") || authenticate(r, "Basic abd") || authenticate(r, "Basic ab") {
		t.Fatal("authenticate compared incorrectly")
	}
}

func TestProxyAuthorizedThrottlesFailures(t *testing.T) {
	authFailures.Lock()
	authFailures.m = map[string]*authFail{}
	authFailures.Unlock()
	do := func(header string) int {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.RemoteAddr = "192.0.2.7:1234"
		if header != "" {
			r.Header.Set("Proxy-Authorization", header)
		}
		w := httptest.NewRecorder()
		if proxyAuthorized(w, r, "Basic good") {
			return http.StatusOK
		}
		return w.Code
	}
	for range 20 { // challenges without credentials are never counted
		if got := do(""); got != http.StatusProxyAuthRequired {
			t.Fatalf("challenge status=%d", got)
		}
	}
	for range authMaxFailures {
		if got := do("Basic bad"); got != http.StatusProxyAuthRequired {
			t.Fatalf("bad credential status=%d", got)
		}
	}
	if got := do("Basic good"); got != http.StatusTooManyRequests {
		t.Fatalf("blocked source status=%d", got)
	}
}

func TestRemoveProxyHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic x")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Connection", "X-Hop, close")
	h.Set("X-Hop", "1")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Accept", "*/*")
	removeProxyHeaders(h)
	if len(h) != 1 || h.Get("Accept") != "*/*" {
		t.Fatalf("headers left: %v", h)
	}
}

func TestCheckCredentialPair(t *testing.T) {
	for _, c := range []struct {
		u, p string
		ok   bool
	}{{"", "", true}, {"u", "p", true}, {"u", "", false}, {"", "p", false}} {
		if err := checkCredentialPair(c.u, c.p); (err == nil) != c.ok {
			t.Fatalf("checkCredentialPair(%q,%q)=%v", c.u, c.p, err)
		}
	}
}
