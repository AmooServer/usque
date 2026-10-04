//go:build linux

package clientstats

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return safeError()
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return safeError()
	}
	// The directory is installed for the unprivileged native writer.
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return safeError()
	}
	return nil
}
func openSecure(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0777 != mode {
		_ = unix.Close(fd)
		return nil, safeError()
	}
	return os.NewFile(uintptr(fd), path), nil
}
func readSecure(path string) (*os.File, error) { return openSecure(path, unix.O_RDONLY, 0640) }
func lockPath(path string) (*os.File, error) {
	f, err := openSecure(path, unix.O_CREAT|unix.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = f.Close()
		return nil, safeError()
	}
	return f, nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
func releaseLock(f *os.File) { _ = f.Close() }
