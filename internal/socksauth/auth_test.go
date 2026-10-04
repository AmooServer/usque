package socksauth

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseCredentials(t *testing.T) {
	c, err := parseCredentials([]byte(`{"username":"example-user","password":"example-password"}`))
	if err != nil || c.Username != "example-user" || c.Password != "example-password" {
		t.Fatal("valid SOCKS credentials were not loaded")
	}
	for _, formatted := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(formatted, "example-user") || strings.Contains(formatted, "example-password") {
			t.Fatal("credentials leaked through formatting")
		}
	}
}

func TestParseCredentialsRejectsInvalidInputWithoutDisclosure(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{`), []byte(`null`), []byte(`[]`), []byte(`{}`),
		[]byte(`{"username":"secret-marker"}`), []byte(`{"password":"secret-marker"}`),
		[]byte(`{"username":"","password":"secret-marker"}`),
		[]byte(`{"username":"secret-marker","password":""}`),
		[]byte(`{"username":123,"password":"secret-marker"}`),
		[]byte(`{"username":"u","password":"secret-marker","other":"secret-marker"}`),
		[]byte(`{"username":"u","username":"v","password":"secret-marker"}`),
		[]byte(`{"username":"u","password":"secret-marker"} {}`),
		[]byte(`{"username":"` + strings.Repeat("u", 256) + `","password":"secret-marker"}`),
		[]byte(`{"username":"u","password":"` + strings.Repeat("é", 128) + `"}`),
		[]byte(strings.Repeat(" ", 4097)),
		append([]byte(`{"username":"u","password":"`), 0xff, '"', '}'),
	} {
		_, err := parseCredentials(data)
		if err == nil {
			t.Fatal("invalid credentials accepted")
		}
		if strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("credential error disclosed input")
		}
	}
	_, err := parseCredentials([]byte(`{"username":"` + strings.Repeat("u", 255) + `","password":"` + strings.Repeat("p", 255) + `"}`))
	if err != nil {
		t.Fatal("255-byte SOCKS credentials rejected")
	}
}
