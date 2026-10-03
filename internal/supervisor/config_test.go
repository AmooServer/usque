package supervisor

import (
	"slices"
	"strings"
	"testing"
)

func TestServiceDefaultsAndChildArguments(t *testing.T) {
	c, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if c.SOCKSAddress() != "127.0.0.1:903" || c.Mode != "socks" || c.MTU != 1280 || c.HealthFailures != 3 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if !slices.Contains(c.ChildArgs(), "--always-reconnect=true") || !slices.Contains(c.ChildArgs(), "--dial-timeout") {
		t.Fatalf("missing production flags: %v", c.ChildArgs())
	}
	c.Mode = "l4-socks"
	if slices.Contains(c.ChildArgs(), "--mtu") || slices.Contains(c.ChildArgs(), "--always-reconnect=true") {
		t.Fatalf("unsupported l4 flags: %v", c.ChildArgs())
	}
}

func TestServiceDNSUsesUpstreamDefaultsWhenUnset(t *testing.T) {
	c, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DNS) != 0 || slices.Contains(c.ChildArgs(), "--dns") {
		t.Fatalf("empty DNS must preserve core defaults: %v", c.ChildArgs())
	}
}

func TestServiceDNSChildArguments(t *testing.T) {
	servers := []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}
	for _, mode := range []string{"socks", "l4-socks"} {
		t.Run(mode, func(t *testing.T) {
			c, err := FromEnvironment(func(key string) string {
				return map[string]string{"USQUE_MODE": mode, "USQUE_DNS": strings.Join(servers, ",")}[key]
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.DNS, servers) {
				t.Fatalf("DNS order changed: %v", c.DNS)
			}
			args := c.ChildArgs()
			var got []string
			for i := 0; i < len(args); i++ {
				if args[i] == "--dns" {
					i++
					if i >= len(args) {
						t.Fatal("missing DNS flag value")
					}
					got = append(got, args[i])
				}
			}
			if !slices.Equal(got, servers) {
				t.Fatalf("DNS flags: %v", got)
			}
		})
	}
}

func TestServiceDNSRejectsInvalidLists(t *testing.T) {
	for _, value := range []string{
		"resolver.example", "1.1.1.1:53", "[::1]", "fe80::1%eth0", ",1.1.1.1", "1.1.1.1,", "1.1.1.1,,1.0.0.1",
		"1.1.1.1, 1.0.0.1", "1.1.1.1\n1.0.0.1", "$(touch /tmp/injected)", "1.1.1.1;echo", "--http2",
		strings.Repeat("1.1.1.1,", 8) + "1.0.0.1",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := FromEnvironment(func(key string) string {
				if key == "USQUE_DNS" {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatal("invalid DNS setting accepted")
			}
		})
	}
	c, err := FromEnvironment(func(key string) string {
		if key == "USQUE_DNS" {
			return strings.Repeat("1.1.1.1,", 7) + "1.0.0.1"
		}
		return ""
	})
	if err != nil || len(c.DNS) != 8 {
		t.Fatalf("eight DNS addresses should be accepted: %v", err)
	}
}

func TestEnvironmentRejectsUnsafeAndInvalidSettings(t *testing.T) {
	for key, value := range map[string]string{
		"USQUE_BIND": "0.0.0.0", "USQUE_PORT": "0", "USQUE_MTU": "1", "USQUE_MODE": "http-proxy",
		"USQUE_HEALTH_TIMEOUT": "0s", "USQUE_HEALTH_INTERVAL": "oops", "USQUE_HEALTH_FAILURES": "0",
		"USQUE_HTTP2": "yes please", "USQUE_BINARY": "relative", "USQUE_BACKOFF_MAX": "1ns",
		"USQUE_HEALTH_URL": "http://trace.example", "USQUE_ALLOW_PUBLIC": "not-a-bool",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := FromEnvironment(func(k string) string {
				if k == key {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
	_, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_MODE": "l4-socks", "USQUE_HTTP2": "true"}[k] })
	if err == nil {
		t.Fatal("unsupported l4 HTTP2 accepted")
	}
	c, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_BIND": "::", "USQUE_ALLOW_PUBLIC": "true"}[k] })
	if err != nil || c.SOCKSAddress() != "[::1]:903" {
		t.Fatalf("explicit public IPv6 opt-in: %+v %v", c, err)
	}
}

func TestTransportsDefaultToHTTP2Setting(t *testing.T) {
	c, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_HTTP2": "true"}[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Transports) != 1 || c.Transports[0] != (Transport{HTTP2: true, Port: 443}) {
		t.Fatalf("unexpected default transports: %+v", c.Transports)
	}
	if !slices.Contains(c.ChildArgs(), "--http2=true") || slices.Contains(c.ChildArgs(), "--connect-port") {
		t.Fatalf("default transport must keep previous arguments: %v", c.ChildArgs())
	}
}

func TestTransportsParseAndChildArguments(t *testing.T) {
	c, err := FromEnvironment(func(k string) string {
		return map[string]string{"USQUE_TRANSPORTS": "quic:443,http2:443,quic:4500"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Transport{{Port: 443}, {HTTP2: true, Port: 443}, {Port: 4500}}
	if !slices.Equal(c.Transports, want) {
		t.Fatalf("transports: %+v", c.Transports)
	}
	if got := c.Transports[2].String(); got != "quic:4500" {
		t.Fatalf("transport name: %s", got)
	}
	args := c.ChildArgsFor(c.Transports[2])
	if !slices.Contains(args, "--http2=false") || !slices.Contains(args, "--connect-port") || !slices.Contains(args, "4500") {
		t.Fatalf("quic:4500 arguments: %v", args)
	}
	if args := c.ChildArgsFor(c.Transports[1]); !slices.Contains(args, "--http2=true") {
		t.Fatalf("http2 arguments: %v", args)
	}
}

func TestTransportsRejectInvalidValues(t *testing.T) {
	for _, value := range []string{"quic", "quic:0", "quic:70000", "tcp:443", "quic:443,", ",quic:443", "quic:443 ,http2:443", "http2:abc",
		strings.Repeat("quic:443,", 8) + "quic:443"} {
		t.Run(value, func(t *testing.T) {
			_, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_TRANSPORTS": value}[k] })
			if err == nil {
				t.Fatal("invalid transports accepted")
			}
		})
	}
	_, err := FromEnvironment(func(k string) string {
		return map[string]string{"USQUE_MODE": "l4-socks", "USQUE_TRANSPORTS": "quic:443,http2:443"}[k]
	})
	if err == nil {
		t.Fatal("l4-socks HTTP2 transport accepted")
	}
}
