//go:build !windows

package main_test

import (
	"os/exec"
	"syscall"
)

func prepareProcess(cmd *exec.Cmd) {}

func stopProcess(cmd *exec.Cmd) error {
	return cmd.Process.Signal(syscall.SIGTERM)
}
