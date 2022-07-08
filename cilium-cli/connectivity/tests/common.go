// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"fmt"
	"net"

	"github.com/cilium/cilium-cli/connectivity/check"
)

func curl(peer check.TestPeer, opts ...string) []string {
	cmd := []string{"curl",
		"-w", "%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}",
		"--silent", "--fail", "--show-error",
		"--connect-timeout", "5",
		"--output", "/dev/null",
	}
	cmd = append(cmd, opts...)
	cmd = append(cmd, fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(), fmt.Sprint(peer.Port())),
		peer.Path()))
	return cmd
}

func ping(peer check.TestPeer) []string {
	return []string{"ping", "-w", "3", "-c", "1", peer.Address()}
}
