// Package socksauth loads private SOCKS credentials without exposing their contents.
package socksauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"unicode/utf8"
)

const maxFileSize = 4096

var (
	errInvalidFile        = errors.New("SOCKS auth file must be an absolute regular file owned by root:usque with mode 0640 and no symlink")
	errInvalidCredentials = errors.New("SOCKS auth file must contain only username and password, each 1..255 UTF-8 bytes")
)

type Credentials struct{ Username, Password string }

func (Credentials) String() string   { return "[redacted SOCKS credentials]" }
func (Credentials) GoString() string { return "[redacted SOCKS credentials]" }

// Load validates the opened file, then reads a bounded JSON object. Errors never include input.
func Load(path string) (Credentials, error) {
	if !filepath.IsAbs(path) {
		return Credentials{}, errInvalidFile
	}
	f, err := openPrivateFile(path)
	if err != nil {
		return Credentials{}, errInvalidFile
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Credentials{}, errInvalidFile
	}
	return parseCredentials(data)
}

func parseCredentials(data []byte) (Credentials, error) {
	var c Credentials
	if len(data) > maxFileSize || !utf8.Valid(data) {
		return c, errInvalidCredentials
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return c, errInvalidCredentials
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (key != "username" && key != "password") {
			return Credentials{}, errInvalidCredentials
		}
		seen[key] = true
		var value string
		if err := d.Decode(&value); err != nil || len(value) < 1 || len(value) > 255 || !utf8.ValidString(value) {
			return Credentials{}, errInvalidCredentials
		}
		if key == "username" {
			c.Username = value
		} else {
			c.Password = value
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !seen["username"] || !seen["password"] {
		return Credentials{}, errInvalidCredentials
	}
	if _, err := d.Token(); err != io.EOF {
		return Credentials{}, errInvalidCredentials
	}
	return c, nil
}
