// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// XfrmStateInfo represents the key information from an XFRM state
// This struct is used for JSON serialization of XFRM state information
// and is shared between cilium-dbg and cilium-cli for consistency
type XfrmStateInfo struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	SPI      uint32 `json:"spi"`
	ReqID    uint32 `json:"reqid"`
	AuthAlg  string `json:"auth_alg,omitempty"`
	AuthKey  string `json:"auth_key,omitempty"`
	CryptAlg string `json:"crypt_alg,omitempty"`
	CryptKey string `json:"crypt_key,omitempty"`
	AeadAlg  string `json:"aead_alg,omitempty"`
	AeadKey  string `json:"aead_key,omitempty"`
}

// DumpXfrmStates extracts XFRM state information using netlink
func DumpXfrmStates() ([]XfrmStateInfo, error) {
	states, err := safenetlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list XFRM states: %w", err)
	}

	var result []XfrmStateInfo
	for _, state := range states {
		// Only include Cilium-managed states (reqid 1)
		if state.Reqid != 1 {
			continue
		}

		xfrmState := XfrmStateInfo{
			Src:   state.Src.String(),
			Dst:   state.Dst.String(),
			SPI:   uint32(state.Spi),
			ReqID: uint32(state.Reqid),
		}

		// Extract authentication algorithm and key
		if state.Auth != nil {
			xfrmState.AuthAlg = state.Auth.Name
			if len(state.Auth.Key) > 0 {
				xfrmState.AuthKey = hex.EncodeToString(state.Auth.Key)
			}
		}

		// Extract encryption algorithm and key
		if state.Crypt != nil {
			xfrmState.CryptAlg = state.Crypt.Name
			if len(state.Crypt.Key) > 0 {
				xfrmState.CryptKey = hex.EncodeToString(state.Crypt.Key)
			}
		}

		// Extract AEAD algorithm and key
		if state.Aead != nil {
			xfrmState.AeadAlg = state.Aead.Name
			if len(state.Aead.Key) > 0 {
				xfrmState.AeadKey = hex.EncodeToString(state.Aead.Key)
			}
		}

		result = append(result, xfrmState)
	}

	return result, nil
}

const (
	maskStateDir = 0xf00
	markStateIn  = 0xd00
	markStateOut = 0xe00
)

func CountUniqueIPsecKeys(states []netlink.XfrmState) (int, error) {
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
		return len(keys), errors.New("an unsupported XfrmStateAlgo combination has been found")
	}
	return len(keys), nil
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
