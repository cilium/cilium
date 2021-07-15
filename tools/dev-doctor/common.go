// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package main

import "os/exec"

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
