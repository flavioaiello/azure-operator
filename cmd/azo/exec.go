package main

import (
	"os"
	"os/exec"
)

// NewExecCommand creates a new exec.Cmd with the given name and arguments.
// It sets up the command to use the current working directory and inherit
// the environment.
func NewExecCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	// SECURITY: Getwd failure defaults to empty string (current dir), acceptable for CLI.
	cmd.Dir, _ = os.Getwd() //nolint:errcheck // Fallback to current directory is acceptable
	cmd.Env = os.Environ()
	return cmd
}
