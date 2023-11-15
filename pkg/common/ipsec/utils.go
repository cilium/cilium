// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"fmt"
	"os"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
)

const (
	maskStateDir = 0xf00
	markStateIn  = 0xd00
	markStateOut = 0xe00
)

func CountUniqueIPsecKeys(states []netlink.XfrmState) int {
	keys := make(map[string]bool)
	invalidStateFound := false
	for _, s := range states {
		if s.Aead != nil && s.Auth == nil && s.Crypt == nil {
			keys[string(s.Aead.Key)] = true
			continue
		}
		if s.Aead == nil && s.Auth != nil && s.Crypt != nil {
			// we want to count the number of unique (Auth, Crypt) tuples
			key := fmt.Sprintf("%s:%s", string(s.Auth.Key), string(s.Crypt.Key))
			keys[key] = true
			continue
		}
		invalidStateFound = true
	}
	if invalidStateFound {
		fmt.Fprintf(os.Stderr, "an unsupported XfrmStateAlgo combination has been found\n")
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

func GetSPIFromXfrmPolicy(policy *netlink.XfrmPolicy) uint8 {
	if policy.Mark == nil {
		return 0
	}

	return ipSecXfrmMarkGetSPI(policy.Mark.Value)
}

// ipSecXfrmMarkGetSPI extracts from a XfrmMark value the encoded SPI
func ipSecXfrmMarkGetSPI(markValue uint32) uint8 {
	return uint8(markValue >> linux_defaults.IPsecXFRMMarkSPIShift & 0xF)
}

func GetNodeIDFromXfrmMark(mark *netlink.XfrmMark) uint16 {
	if mark == nil {
		return 0
	}
	return uint16(mark.Value >> 16)
}
