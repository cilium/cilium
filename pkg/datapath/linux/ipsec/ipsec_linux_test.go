// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/testutils"
	tnl "github.com/cilium/cilium/pkg/testutils/netlink"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func mustParseCIDR(tb testing.TB, s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	require.NoError(tb, err)
	return ipNet
}

func setup(tb testing.TB, family string) (local, remote *net.IPNet) {
	testutils.PrivilegedTest(tb)

	require.NoError(tb, rlimit.RemoveMemlock())
	log = hivetest.Logger(tb)

	switch family {
	case "ipv4":
		return mustParseCIDR(tb, "1.1.3.4/16"), mustParseCIDR(tb, "1.2.3.4/16")
	case "ipv6":
		return mustParseCIDR(tb, "2001:0:0:1134::/64"), mustParseCIDR(tb, "2001:0:0:1234::/64")
	}

	tb.Fatalf("unknown family: %s", family)
	return
}

const (
	path         = "ipsec_keys_test"
	remoteNodeID = 1234
	localBootID  = "5f616d5f-b237-aed6-4ac7-123456789abc"
	remoteBootID = "5f616d5f-aed6-4ac7-b237-987654321abc"
)

var (
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n2 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n")
	keysNullDat    = []byte("3 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("4 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	keysAeadDat256 = []byte("5 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f144434241343332312423222114131211 128\n")
	invalidKeysDat = []byte("6 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
	keysSameSpiDat = []byte("7 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n7 digest_null \"\" cipher_null \"\"\n")

	log *slog.Logger
)

var families = []string{"ipv4", "ipv6"}

func testWithFamilies(t *testing.T, f func(t *testing.T, family string)) {
	t.Helper()

	for _, family := range families {
		t.Run(family, func(t *testing.T) {
			f(t, family)
		})
	}
}

func mustUpsertIPSecEndpoint(tb testing.TB, ns *netns.NetNS, a *agent, params *types.Parameters) {
	tb.Helper()

	require.NoError(tb, ns.Do(func() error {
		_, err := a.UpsertIPsecEndpoint(params)
		return err
	}))
}

func TestLoadKeysNoFile(t *testing.T) {
	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	_, err = a.loadIPSecKeysFile(path)
	require.True(t, os.IsNotExist(err))
}

func TestPrivilegedInvalidLoadKeys(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testInvalidLoadKeys(t, family)
	})
}

func testInvalidLoadKeys(t *testing.T, family string) {
	local, remote := setup(t, family)

	testCases := []struct {
		name     string
		input    []byte
		expError string
	}{
		{"invalid keys", invalidKeysDat, "unable to decode authentication key string"},
		{"empty line", []byte(" \n"), "missing IPSec key or invalid format"},
		{"blank second line", []byte("4 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n   \n"), "missing IPSec key or invalid format"},
		{"leading space", []byte(" rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"), "the first argument of the IPsec secret is not a number"},
		{"spi plus only", []byte("+ rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n"), "the first argument of the IPsec secret is not a number"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewTestIPsecAgent(t, nil)
			require.NoError(t, err)
			keys := bytes.NewReader(tc.input)
			_, err = a.loadIPSecKeys(keys)
			require.ErrorContains(t, err, tc.expError)
		})
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   remoteNodeID,
		Dir:            IPSecDirIn,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &local.IP,
		DestTunnelIP:   &remote.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = a.UpsertIPsecEndpoint(params)
	require.Error(t, err)
}

func TestLoadKeys(t *testing.T) {
	testCases := [][]byte{keysDat, keysNullDat, keysAeadDat, keysAeadDat256}
	for _, testCase := range testCases {
		keys := bytes.NewReader(testCase)
		a, err := NewTestIPsecAgent(t, nil)
		require.NoError(t, err)
		spi, err := a.loadIPSecKeys(keys)
		require.NoError(t, err)
		err = a.setIPSecSPI(spi)
		require.NoError(t, err)
		require.Equal(t, spi, a.spi)
	}
}

func TestLoadKeysLenChange(t *testing.T) {
	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	keys := bytes.NewReader(append(keysDat, keysNullDat...))
	_, err = a.loadIPSecKeys(keys)
	require.ErrorContains(t, err, "invalid key rotation: key length must not change")
}

func TestLoadKeysSameSPI(t *testing.T) {
	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	keys := bytes.NewReader(keysSameSpiDat)
	_, err = a.loadIPSecKeys(keys)
	require.ErrorContains(t, err, "invalid SPI: changing IPSec keys requires incrementing the key id")
}

func TestParseSPI(t *testing.T) {
	testCases := []struct {
		input    string
		expSPI   uint8
		expOff   int
		expError bool
	}{
		{"254", 0, 0, true},
		{"15", 15, 0, false},
		{"3+", 3, 0, false},
		{"abc", 0, 0, true},
		{"0", 0, 0, true},
		{"+", 0, 0, true},
	}
	for _, tc := range testCases {
		spi, off, err := parseSPI(tc.input)
		if spi != tc.expSPI {
			t.Fatalf("For input %q, expected SPI %d, but got %d", tc.input, tc.expSPI, spi)
		}
		if off != tc.expOff {
			t.Fatalf("For input %q, expected base offset %d, but got %d", tc.input, tc.expOff, off)
		}
		if tc.expError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestPrivilegedUpsertIPSecEquals(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpsertIPSecEquals(t, family)
	})
}

func testUpsertIPSecEquals(t *testing.T, family string) {
	_, remote := setup(t, family)

	// Set source and destination to same IP.
	local := remote

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	a.key = key

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   remoteNodeID,
		Dir:            IPSecDirIn,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &local.IP,
		DestTunnelIP:   &remote.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	ns := netns.NewNetNS(t)
	mustUpsertIPSecEndpoint(t, ns, a, params)

	// Let's check that state was not added as source and destination are the same
	result := tnl.MustXfrmStateList(t, ns, netlink.FAMILY_ALL)
	require.Empty(t, result)

	mustUpsertIPSecEndpoint(t, ns, a, params)

	// Let's check that state was not added as source and destination are the same
	result = tnl.MustXfrmStateList(t, ns, netlink.FAMILY_ALL)
	require.Empty(t, result)
}

func TestPrivilegedUpsertIPSecEndpointOut(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpsertIPSecEndpointOut(t, family)
	})
}

// TestUpsertIPSecEndpointOut ensure we insert the correct XFRM policy when
// specifying the OUT direction.
//
// For the OUT direction the following properties are true:
// 1. A OUT policy should be created with the following properties:
//
//   - The source subnet selector should be the local subnet
//   - The destination subnet selector should be the remote subnet
//   - The source tunnel endpoint IP should be the local end of the SA
//   - The destination tunnel endpoint IP should be the remote end of the SA
//   - The policy's mark should be a composite of the remote NodeID, the SPI, and
//     the well-defined Encryption mark.
//
// 2. A state should be created with similar properties as above.
func testUpsertIPSecEndpointOut(t *testing.T, family string) {
	local, remote := setup(t, family)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	a.key = key

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirOut,
		SourceSubnet:   local,
		DestSubnet:     remote,
		SourceTunnelIP: &local.IP,
		DestTunnelIP:   &remote.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	ns := netns.NewNetNS(t)
	mustUpsertIPSecEndpoint(t, ns, a, params)

	encryptionMark := generateEncryptMark(key.Spi, params.RemoteNodeID)

	// Confirm state was created with correct marks.
	getState := &netlink.XfrmState{
		Src:   local.IP,
		Dst:   remote.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark:  encryptionMark}

	state := tnl.MustXfrmStateGet(t, ns, getState)
	require.NotNil(t, state)

	require.Nil(t, state.Aead)
	require.NotNil(t, state.Auth)
	require.Equal(t, "hmac(sha256)", state.Auth.Name)
	derivedAuthKey := computeNodeIPsecKey(authKey, local.IP, remote.IP, []byte(localBootID), []byte(remoteBootID))
	require.Equal(t, derivedAuthKey, state.Auth.Key)
	require.NotNil(t, state.Crypt)
	require.Equal(t, "cbc(aes)", state.Crypt.Name)
	derivedCryptKey := computeNodeIPsecKey(cryptKey, local.IP, remote.IP, []byte(localBootID), []byte(remoteBootID))
	require.Equal(t, derivedCryptKey, state.Crypt.Key)
	// ESN bit is not set, so ReplayWindow should be 0
	require.Equal(t, 0, state.ReplayWindow)
	require.Equal(t, state.Mark, encryptionMark)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:   local.IP,
			Dst:   remote.IP,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: params.ReqID,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy := tnl.MustXfrmPolicyGet(t, ns, &netlink.XfrmPolicy{
		Src:   local,
		Dst:   remote,
		Dir:   netlink.XFRM_DIR_OUT,
		Mark:  generateEncryptMark(key.Spi, params.RemoteNodeID),
		Tmpls: tmpls,
	})
	require.NotNil(t, policy)

	// ensure XFRM policy is as we want it...
	if !policy.Src.IP.Equal(local.IP) {
		t.Fatalf("Expected Src to be %s, but got %s", local.IP.String(), policy.Src.IP.String())
	}
	if !policy.Dst.IP.Equal(remote.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", remote.IP.String(), policy.Dst.IP.String())
	}
	require.Equal(t, netlink.XFRM_DIR_OUT, policy.Dir)
	require.Equal(t, policy.Mark, encryptionMark)
	require.Len(t, policy.Tmpls, 1)

	// ensure the template is correct as well...
	policyTmpl := policy.Tmpls[0]
	if !policyTmpl.Src.Equal(local.IP) {
		t.Fatalf("Expected Src to be %s, but got %s", local.IP.String(), policyTmpl.Src.String())
	}
	if !policyTmpl.Dst.Equal(remote.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", remote.IP.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, params.ReqID, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)
}

func TestPrivilegedUpsertIPSecEndpointFwd(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpsertIPSecEndpointFwd(t, family)
	})
}

// TestUpsertIPSecEndpointFwd ensure we insert the correct XFRM policy when
// specifying the FWD direction.
//
// For the FWD direction the following properties are true:
// 1. A FWD policy should be created with the following properties
//
//   - Source and Destination subnets are wildcard (0.0.0.0/0).
//   - Priority is low at 2975
//   - Template source is undefined (0.0.0.0)
//   - Template destination is the ESP tunnel IP of the local node forwarding
//     the traffic.
//   - A ReqID of 1
func testUpsertIPSecEndpointFwd(t *testing.T, family string) {
	local, _ := setup(t, family)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	a.key = key

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirFwd,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &net.IP{},
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	ns := netns.NewNetNS(t)
	mustUpsertIPSecEndpoint(t, ns, a, params)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:      net.IP{},
			Dst:      local.IP,
			Proto:    netlink.XFRM_PROTO_ESP,
			Reqid:    params.ReqID,
			Mode:     netlink.XFRM_MODE_TUNNEL,
			Optional: 1,
		},
	}

	policy := tnl.MustXfrmPolicyGet(t, ns, &netlink.XfrmPolicy{
		Src:   wildcardCIDRv4,
		Dst:   wildcardCIDRv4,
		Dir:   netlink.XFRM_DIR_FWD,
		Tmpls: tmpls,
	})
	require.NotNil(t, policy)

	// ensure XFRM policy is as we want it...
	if !policy.Src.IP.Equal(wildcardIPv4) {
		t.Fatalf("Expected Src to be %s, but got %s", wildcardIPv4.String(), policy.Src.IP.String())
	}
	if !policy.Dst.IP.Equal(wildcardIPv4) {
		t.Fatalf("Expected Dst to be %s, but got %s", wildcardIPv4.String(), policy.Dst.IP.String())
	}
	require.Equal(t, netlink.XFRM_DIR_FWD, policy.Dir)
	require.Nil(t, policy.Mark)
	require.Len(t, policy.Tmpls, 1)

	// ensure the template is correct as well...
	policyTmpl := policy.Tmpls[0]
	if !policyTmpl.Src.Equal(wildcardIPv4) {
		t.Fatalf("Expected Src to be %s, but got %s", wildcardIPv4.String(), policyTmpl.Src.String())
	}
	if !policyTmpl.Dst.Equal(wildcardIPv4) {
		t.Fatalf("Expected Dst to be %s, but got %s", wildcardIPv4.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, 0, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)
	require.Equal(t, 1, policyTmpl.Optional)
}

func TestPrivilegedUpsertIPSecEndpointIn(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpsertIPSecEndpointIn(t, family)
	})
}

// TestUpsertIPSecEndpointIn ensures we insert the correct XFRM state and
// policy when specifying the IN direction.
//
// For the IN direction the following properties are true:
// 1. An IN policy should be created with the following properties
//
//   - The source subnet selector should be the remote subnet
//   - The destination subnet selector should be the local subnet
//   - The source tunnel endpoint IP should be the remote end of the SA
//   - The destination tunnel endpoint IP should be the local end of the SA
//   - The policy's mark should be a composite of the remote NodeID and the
//     well-defined Decryption mark.
//   - An additional policy should be created, with similar properties, with
//     the exception that the mark match should be the TO_PROXY mark.
//
// 2. A state should be created with similar properties as above.
func testUpsertIPSecEndpointIn(t *testing.T, family string) {
	local, remote := setup(t, family)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	a.key = key

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirIn,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	ns := netns.NewNetNS(t)
	mustUpsertIPSecEndpoint(t, ns, a, params)

	// Confirm state was created with correct marks.
	getState := &netlink.XfrmState{
		Src:   remote.IP,
		Dst:   local.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark:  generateDecryptMark(linux_defaults.RouteMarkDecrypt, params.RemoteNodeID)}

	state := tnl.MustXfrmStateGet(t, ns, getState)
	require.NotNil(t, state)

	require.Nil(t, state.Aead)
	require.NotNil(t, state.Auth)
	require.Equal(t, "hmac(sha256)", state.Auth.Name)
	derivedAuthKey := computeNodeIPsecKey(authKey, remote.IP, local.IP, []byte(remoteBootID), []byte(localBootID))
	require.Equal(t, derivedAuthKey, state.Auth.Key)
	require.NotNil(t, state.Crypt)
	require.Equal(t, "cbc(aes)", state.Crypt.Name)
	derivedCryptKey := computeNodeIPsecKey(cryptKey, remote.IP, local.IP, []byte(remoteBootID), []byte(localBootID))
	require.Equal(t, derivedCryptKey, state.Crypt.Key)
	// ESN bit is not set, so ReplayWindow should be 0
	require.Equal(t, 0, state.ReplayWindow)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:   wildcardIPv4,
			Dst:   wildcardIPv4,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: 0,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy := tnl.MustXfrmPolicyGet(t, ns, &netlink.XfrmPolicy{
		Src:   wildcardCIDRv4,
		Dst:   wildcardCIDRv4,
		Dir:   netlink.XFRM_DIR_IN,
		Tmpls: tmpls,
	})
	require.NotNil(t, policy)

	// ensure XFRM policy is as we want it...
	if !policy.Src.IP.Equal(wildcardIPv4) {
		t.Fatalf("Expected Src to be %s, but got %s", wildcardIPv4.String(), policy.Src.IP.String())
	}
	if !policy.Dst.IP.Equal(wildcardIPv4) {
		t.Fatalf("Expected Dst to be %s, but got %s", wildcardIPv4.String(), policy.Dst.IP.String())
	}
	require.Equal(t, netlink.XFRM_DIR_IN, policy.Dir)
	require.Nil(t, policy.Mark)
	require.Len(t, policy.Tmpls, 1)

	// ensure the template is correct as well...
	policyTmpl := policy.Tmpls[0]
	if !policyTmpl.Src.Equal(wildcardIPv4) {
		t.Fatalf("Expected Src to be %s, but got %s", wildcardIPv4.String(), policyTmpl.Src.String())
	}
	if !policyTmpl.Dst.Equal(wildcardIPv4) {
		t.Fatalf("Expected Dst to be %s, but got %s", wildcardIPv4.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, 0, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)
}

func TestPrivilegedUpsertIPSecKeyMissing(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpsertIPSecKeyMissing(t, family)
	})
}

func testUpsertIPSecKeyMissing(t *testing.T, family string) {
	local, remote := setup(t, family)

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   remoteNodeID,
		Dir:            IPSecDirIn,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	ns := netns.NewNetNS(t)
	err = ns.Do(func() error {
		_, err := a.UpsertIPsecEndpoint(params)
		return err
	})
	require.ErrorContains(t, err, "unable to replace local state: global IPsec key missing")
}

func TestPrivilegedUpdateExistingIPSecEndpoint(t *testing.T) {
	testWithFamilies(t, func(t *testing.T, family string) {
		testUpdateExistingIPSecEndpoint(t, family)
	})
}

func testUpdateExistingIPSecEndpoint(t *testing.T, family string) {
	local, remote := setup(t, family)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	a, err := NewTestIPsecAgent(t, nil)
	require.NoError(t, err)
	a.key = key

	params := &types.Parameters{
		LocalBootID:    localBootID,
		RemoteBootID:   remoteBootID,
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirIn,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	ns := netns.NewNetNS(t)
	mustUpsertIPSecEndpoint(t, ns, a, params)

	// test updateExisting (xfrm delete + add)
	mustUpsertIPSecEndpoint(t, ns, a, params)
}

func TestGetDirFromXfrmMark(t *testing.T) {
	tests := []struct {
		name string
		mark *netlink.XfrmMark
		want dir
	}{
		{
			name: "Should return ingress for decrypt mark",
			mark: &netlink.XfrmMark{
				Value: 0xcb200d00,
			},
			want: dirIngress,
		},
		{
			name: "Should return egress for encrypt mark",
			mark: &netlink.XfrmMark{
				Value: 0xcb200e00,
			},
			want: dirEgress,
		},
		{
			name: "Should return unspec for nil mark",
			mark: nil,
			want: dirUnspec,
		},
		{
			name: "Should return unspec for invalid mark",
			mark: &netlink.XfrmMark{
				Value: 0xcb200a1b,
			},
			want: dirUnspec,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, getDirFromXfrmMark(tt.mark))
		})
	}
}
