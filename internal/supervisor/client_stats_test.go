package supervisor

import (
	"slices"
	"strings"
	"testing"
)

func TestClientStatsPathReachesBothSOCKSChildren(t *testing.T) {
	for _, mode := range []string{"socks", "l4-socks"} {
		t.Run(mode, func(t *testing.T) {
			c, err := FromEnvironment(func(key string) string {
				return map[string]string{"USQUE_MODE": mode, "USQUE_CLIENT_STATS_FILE": "/var/lib/usque-clients/clients.json"}[key]
			})
			if err != nil {
				t.Fatal(err)
			}
			args := c.ChildArgs()
			position := slices.Index(args, "--client-stats-file")
			if position < 0 || position+1 >= len(args) || args[position+1] != "/var/lib/usque-clients/clients.json" {
				t.Fatalf("monitoring path was not passed to %s child: %v", mode, args)
			}
		})
	}
}

func TestClientStatsRemainOptional(t *testing.T) {
	c, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(c.ChildArgs(), "--client-stats-file") {
		t.Fatal("legacy profile unexpectedly enabled monitoring")
	}
}

func TestClientStatsEnvironmentRejectsUnsupportedPathsWithoutEcho(t *testing.T) {
	for _, value := range []string{"relative.json", "/tmp/private-marker.json", "/var/lib/usque-clients/../private-marker.json", "$(private-marker)", "/var/lib/usque-clients/clients.json\nprivate-marker"} {
		t.Run(value, func(t *testing.T) {
			_, err := FromEnvironment(func(key string) string {
				if key == "USQUE_CLIENT_STATS_FILE" {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatal("unsupported monitoring path was accepted")
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Fatal("monitoring error echoed configuration input")
			}
		})
	}
}
