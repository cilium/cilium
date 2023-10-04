// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/vishvananda/netlink"
)

func CountUniqueIPsecKeys(states []netlink.XfrmState) int {
	keys := make(map[string]bool)
	for _, s := range states {
		if s.Aead == nil {
			continue
		}
		keys[string(s.Aead.Key)] = true
	}

	return len(keys)
}
