package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func prepareProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
}

func stopProcess(cmd *exec.Cmd) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	helper := exec.Command(path)
	helper.Env = append(os.Environ(), "ACS_TEST_INTERRUPT_PID="+strconv.Itoa(cmd.Process.Pid))
	helper.Stdout = os.Stdout
	helper.Stderr = os.Stderr
	if err := helper.Run(); err != nil {
		return fmt.Errorf("send console interrupt: %w", err)
	}
	return nil
}

func TestMain(m *testing.M) {
	if value := os.Getenv("ACS_TEST_INTERRUPT_PID"); value != "" {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		kernel := windows.NewLazySystemDLL("kernel32.dll")
		_, _, _ = kernel.NewProc("FreeConsole").Call()
		if result, _, err := kernel.NewProc("AttachConsole").Call(uintptr(pid)); result == 0 {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		signal.Ignore(os.Interrupt)
		if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
