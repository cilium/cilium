// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"fmt"
	"net"

	"github.com/cilium/cilium-cli/connectivity/check"
)

func curl(peer check.TestPeer) []string {
	return []string{"curl",
		"-w", "%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}",
		"--silent", "--fail", "--show-error",
		"--connect-timeout", "5",
		"--output", "/dev/null",
		fmt.Sprintf("%s://%s%s",
			peer.Scheme(),
			net.JoinHostPort(peer.Address(), fmt.Sprint(peer.Port())),
			peer.Path()),
	}
}

func ping(peer check.TestPeer) []string {
	return []string{"ping", "-w", "3", "-c", "1", peer.Address()}
}
