// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/vishvananda/netlink"
)

const (
	maskStateDir = 0xf00
	markStateIn  = 0xd00
	markStateOut = 0xe00
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

func CountXfrmStatesByDir(states []netlink.XfrmState) (int, int) {
	nbXfrmIn := 0
	nbXfrmOut := 0
	for _, s := range states {
		if s.Mark == nil {
			continue
		}
		switch s.Mark.Value & maskStateDir {
		case markStateIn:
			nbXfrmIn++
		case markStateOut:
			nbXfrmOut++
		}
	}
	return nbXfrmIn, nbXfrmOut
}

func CountXfrmPoliciesByDir(states []netlink.XfrmPolicy) (int, int, int) {
	nbXfrmIn := 0
	nbXfrmOut := 0
	nbXfrmFwd := 0
	for _, p := range states {
		switch p.Dir {
		case netlink.XFRM_DIR_IN:
			nbXfrmIn++
		case netlink.XFRM_DIR_OUT:
			nbXfrmOut++
		case netlink.XFRM_DIR_FWD:
			nbXfrmFwd++
		}
	}
	return nbXfrmIn, nbXfrmOut, nbXfrmFwd
}
