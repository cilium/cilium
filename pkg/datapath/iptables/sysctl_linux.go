// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"github.com/cilium/cilium/pkg/sysctl"
)

func enableIPForwarding(ipv6 bool) error {
	if err := sysctl.Enable("net.ipv4.ip_forward"); err != nil {
		return err
	}
	if err := sysctl.Enable("net.ipv4.conf.all.forwarding"); err != nil {
		return err
	}
	if ipv6 {
		if err := sysctl.Enable("net.ipv6.conf.all.forwarding"); err != nil {
			return err
		}
	}
	return nil
}
