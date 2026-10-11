package internal

import "testing"

func TestParsePortMapping(t *testing.T) {
	for _, c := range []struct {
		in   string
		want PortMapping
	}{
		{"127.0.0.1:8080:10.0.0.2:80", PortMapping{"127.0.0.1", 8080, "10.0.0.2", 80}},
		{"[::1]:8080:10.0.0.2:80", PortMapping{"::1", 8080, "10.0.0.2", 80}},
		{"[::1]:8080:[fd00::2]:80", PortMapping{"::1", 8080, "fd00::2", 80}},
		{"8080:[fd00::2]:80", PortMapping{"127.0.0.1", 8080, "fd00::2", 80}},
		{"*:8080:10.0.0.2:80", PortMapping{"0.0.0.0", 8080, "10.0.0.2", 80}},
	} {
		got, err := ParsePortMapping(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParsePortMapping(%q)=%+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{"", "8080", "1:2:3:4:5", "[::1:8080:10.0.0.2:80", "[::1]:0:10.0.0.2:80", "[::1]:8080:10.0.0.2:99999"} {
		if _, err := ParsePortMapping(in); err == nil {
			t.Errorf("ParsePortMapping(%q) accepted", in)
		}
	}
}
