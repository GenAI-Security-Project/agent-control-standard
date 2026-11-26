//go:build unix

package guardian

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
)

// auditOpenFlags makes the open fail on a symbolic link at the log path, so
// the Guardian never writes through a link an attacker placed .
const auditOpenFlags = syscall.O_NOFOLLOW

func auditOpenError(path string, err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("audit log %s is a symbolic link; the Guardian does not follow it", path)
	}
	return err
}

// checkAuditFileMode refuses a log that group or other can read or write:
// its records name agents, sessions and tool arguments. The operator sets the
// mode; the Guardian does not chmod a file it did not create.
func checkAuditFileMode(path string, info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("audit log %s has mode %04o; group and other must have no access", path, perm)
	}
	return nil
}
