//go:build !linux

package clientstats

import (
	"os"
	"sync"
)

var otherLocks sync.Map

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return safeError()
	}
	return nil
}
func readSecure(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, safeError()
	}
	return os.Open(path)
}
func lockPath(path string) (*os.File, error) {
	if _, loaded := otherLocks.LoadOrStore(path, true); loaded {
		return nil, safeError()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		otherLocks.Delete(path)
	}
	return f, err
}
func syncDirectory(string) error { return nil }
func releaseLock(f *os.File)     { otherLocks.Delete(f.Name()); _ = f.Close() }
