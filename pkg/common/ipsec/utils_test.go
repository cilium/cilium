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

func getXfrmState(src string, dst string, spi int, key string, mark uint32) netlink.XfrmState {
	k, _ := hex.DecodeString(key)
	return netlink.XfrmState{
		Src:   net.ParseIP(src),
		Dst:   net.ParseIP(dst),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   spi,
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    k,
			ICVLen: 64,
		},
		Mark: &netlink.XfrmMark{
			Value: mark,
			Mask:  0xffffff00,
		},
	}
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

	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.1", "10.0.0.2", 2, "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343e00))
	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.2", "10.0.0.1", 1, "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))

	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 1)

	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.1", "10.0.0.2", 1, "383fa49ea57848c9e85af88a187321f81da54bb6", 0x12343e00))

	keys = CountUniqueIPsecKeys(xfrmStates)
	require.Equal(t, keys, 2)
}

func TestCountXfrmStatesByDir(t *testing.T) {
	var xfrmStates []netlink.XfrmState

	nbIn, nbOut := CountXfrmStatesByDir(xfrmStates)
	require.Equal(t, nbIn, 0)
	require.Equal(t, nbOut, 0)

	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.1", "10.0.0.2", 2, "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343e00))
	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.2", "10.0.0.1", 1, "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))
	xfrmStates = append(xfrmStates, getXfrmState("10.0.0.3", "10.0.0.1", 1, "611d0c8049dd88600ec4f9eded7b1ed540ea607f", 0x12343d00))

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
