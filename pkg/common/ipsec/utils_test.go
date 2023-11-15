// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func getXfrmState(t *testing.T, src string, dst string, spi int, algoName string, key string, mark uint32) netlink.XfrmState {
	k, _ := hex.DecodeString(key)
	state := netlink.XfrmState{
		Src:   net.ParseIP(src),
		Dst:   net.ParseIP(dst),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   spi,
		Mark: &netlink.XfrmMark{
			Value: mark,
			Mask:  0xffffff00,
		},
	}
	switch algoName {
	case "cbc(aes)":
		state.Auth = &netlink.XfrmStateAlgo{
			Name:   "hmac(sha512)",
			Key:    k,
			ICVLen: 64,
		}
		state.Crypt = &netlink.XfrmStateAlgo{
			Name:   "cbc(aes)",
			Key:    k,
			ICVLen: 64,
		}
	case "rfc4106(gcm(aes))":
		state.Aead = &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    k,
			ICVLen: 64,
		}
	default:
		t.Errorf("Unsupported algorithm: %s", algoName)
	}
	return state
}

func getXfrmPolicy(t *testing.T, src string, dst string, dir netlink.Dir) netlink.XfrmPolicy {
	srcCIDR, err := netlink.ParseIPNet(src)
	require.NoError(t, err)
	dstCIDR, err := netlink.ParseIPNet(dst)
	require.NoError(t, err)
	return netlink.XfrmPolicy{
		Dir:   dir,
		Src:   srcCIDR,
		Dst:   dstCIDR,
		Proto: netlink.XFRM_PROTO_ESP,
	}
}

func TestCountUniqueIPsecKeys(t *testing.T) {
	var xfrmStates []netlink.XfrmState

	keys := CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 0)

	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.1", "10.0.0.2", 2, "rfc4106(gcm(aes))", "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343e00))
	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.2", "10.0.0.1", 1, "rfc4106(gcm(aes))", "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))

	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 1)

	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.1", "10.0.0.2", 1, "rfc4106(gcm(aes))", "383fa49ea57848c9e85af88a187321f81da54bb6", 0x12343e00))

	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 2)

	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.1", "10.0.0.2", 1, "cbc(aes)", "a9d204b6c2df6f0b707bbfdb71b4bd44", 0x12343e00))

	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 3)

	state := getXfrmState(t, "10.0.0.1", "10.0.0.2", 2, "cbc(aes)", "123d0c8049dd88600ec4f9eded7b1ed540ea607a", 0x12343e00)
	state.Auth = nil // make it invalid
	xfrmStates = append(xfrmStates, state)
	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 3)

	state = getXfrmState(t, "10.0.0.1", "10.0.0.2", 2, "cbc(aes)", "234d0c8049dd88600ec4f9eded7b1ed540ea607b", 0x12343e00)
	state.Crypt = nil // make it invalid
	xfrmStates = append(xfrmStates, state)
	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 3)

	state = getXfrmState(t, "10.0.0.1", "10.0.0.2", 2, "cbc(aes)", "345d0c8049dd88600ec4f9eded7b1ed540ea607c", 0x12343e00)
	state.Aead = nil  // make it invalid
	state.Auth = nil  // make it invalid
	state.Crypt = nil // make it invalid
	xfrmStates = append(xfrmStates, state)
	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 3)
}

func TestCountXfrmStatesByDir(t *testing.T) {
	var xfrmStates []netlink.XfrmState

	nbIn, nbOut := CountXfrmStatesByDir(xfrmStates)
	require.Equal(t, nbIn, 0)
	require.Equal(t, nbOut, 0)

	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.1", "10.0.0.2", 2, "rfc4106(gcm(aes))", "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343e00))
	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.2", "10.0.0.1", 1, "rfc4106(gcm(aes))", "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))
	xfrmStates = append(xfrmStates, getXfrmState(t, "10.0.0.3", "10.0.0.1", 1, "rfc4106(gcm(aes))", "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))

	nbIn, nbOut = CountXfrmStatesByDir(xfrmStates)
	require.Equal(t, nbIn, 2)
	require.Equal(t, nbOut, 1)
}

func TestCountXfrmPoliciesByDir(t *testing.T) {
	var xfrmPolicies []netlink.XfrmPolicy

	nbIn, nbOut, nbFwd := CountXfrmPoliciesByDir(xfrmPolicies)
	require.Equal(t, nbIn, 0)
	require.Equal(t, nbOut, 0)
	require.Equal(t, nbFwd, 0)

	xfrmPolicies = append(xfrmPolicies, getXfrmPolicy(t, "10.0.1.0/24", "10.0.0.0/24", netlink.XFRM_DIR_IN))
	xfrmPolicies = append(xfrmPolicies, getXfrmPolicy(t, "10.0.0.0/24", "10.0.1.0/24", netlink.XFRM_DIR_OUT))
	xfrmPolicies = append(xfrmPolicies, getXfrmPolicy(t, "10.0.0.0/24", "10.0.2.0/24", netlink.XFRM_DIR_OUT))
	xfrmPolicies = append(xfrmPolicies, getXfrmPolicy(t, "10.0.0.0/16", "10.0.0.0/16", netlink.XFRM_DIR_FWD))

	nbIn, nbOut, nbFwd = CountXfrmPoliciesByDir(xfrmPolicies)
	require.Equal(t, nbIn, 1)
	require.Equal(t, nbOut, 2)
	require.Equal(t, nbFwd, 1)
}
