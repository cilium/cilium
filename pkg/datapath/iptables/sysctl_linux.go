// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

func enableIPForwarding(sysctl sysctl.Sysctl, ipv6 bool) error {
	if err := sysctl.Enable([]string{"net", "ipv4", "ip_forward"}); err != nil {
		return err
	}
	if err := sysctl.Enable([]string{"net", "ipv4", "conf", "all", "forwarding"}); err != nil {
		return err
	}
	if ipv6 {
		if err := sysctl.Enable([]string{"net", "ipv6", "conf", "all", "forwarding"}); err != nil {
			return err
		}
	}
	return nil
}
