// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import "github.com/cilium/cilium/pkg/datapath/linux/sysctl"

// enableIPForwarding on OS X and Darwin is not doing anything. It just exists
// to make compilation possible.
func enableIPForwarding(_ sysctl.Sysctl, _ bool) error {
	return nil
}
