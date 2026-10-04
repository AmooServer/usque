//go:build !linux

package socksauth

import "os"

// The credential-file contract requires Linux ownership and permission checks.
func openPrivateFile(string) (*os.File, error) { return nil, errInvalidFile }
