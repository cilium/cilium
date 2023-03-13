// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

func enableIPForwarding() error {
	if err := sysctl.Enable("net.ipv4.ip_forward"); err != nil {
		return err
	}
	if err := sysctl.Enable("net.ipv4.conf.all.forwarding"); err != nil {
		return err
	}
	if option.Config.EnableIPv6 {
		if err := sysctl.Enable("net.ipv6.conf.all.forwarding"); err != nil {
			return err
		}
	}
	return nil
}
