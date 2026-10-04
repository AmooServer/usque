package socksauth

import (
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

func openPrivateFile(path string) (*os.File, error) {
	g, err := user.LookupGroup("usque")
	if err != nil {
		return nil, errInvalidFile
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return nil, errInvalidFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errInvalidFile
	}
	f := os.NewFile(uintptr(fd), "SOCKS auth file")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0640 || st.Uid != 0 || uint64(st.Gid) != gid || st.Size > maxFileSize {
		_ = f.Close()
		return nil, errInvalidFile
	}
	return f, nil
}
