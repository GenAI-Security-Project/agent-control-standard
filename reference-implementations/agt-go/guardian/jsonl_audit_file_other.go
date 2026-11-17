//go:build !unix

package guardian

import "io/fs"

// Symbolic links are not refused and mode bits are not checked here: those
// platforms do not give the Unix meaning to either.
const auditOpenFlags = 0

func auditOpenError(_ string, err error) error { return err }

func checkAuditFileMode(string, fs.FileInfo) error { return nil }
