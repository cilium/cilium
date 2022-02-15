// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"go/build"
	"os"
	"os/exec"
)

// sudo returns cmd run with sudo. cmd is modified in place.
func sudo(cmd *exec.Cmd) (*exec.Cmd, error) {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return nil, err
	}
	cmd.Args = append([]string{cmd.Path}, cmd.Args...)
	cmd.Path = sudoPath
	return cmd, nil
}

// goPath returns the environment $GOPATH, or the default when empty or unset.
func goPath() string {
	if gp := os.Getenv("GOPATH"); gp != "" {
		return gp
	}
	return build.Default.GOPATH
}
