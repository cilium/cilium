//go:build unparallel

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

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupIPSecSuitePrivileged(tb testing.TB) *slog.Logger {
	testutils.PrivilegedTest(tb)
	node.SetTestLocalNodeStore()
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
	log := hivetest.Logger(tb)

	tb.Cleanup(func() {
		UnsetTestIPSecKey()
		node.UnsetTestLocalNodeStore()
		err := DeleteXFRM(log, AllReqID)
		if err != nil {
			tb.Errorf("Failed cleaning XFRM state: %v", err)
		}
	})
	return log
}

var (
	path           = "ipsec_keys_test"
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n2 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n3 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("4 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	keysAeadDat256 = []byte("5 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f144434241343332312423222114131211 128\n")
	invalidKeysDat = []byte("6 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
	keysSameSpiDat = []byte("7 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n7 digest_null \"\" cipher_null \"\"\n")
)

func TestLoadKeysNoFile(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, _, err := LoadIPSecKeysFile(log, path)
	require.True(t, os.IsNotExist(err))
}

func TestInvalidLoadKeys(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	keys := bytes.NewReader(invalidKeysDat)
	_, _, err := LoadIPSecKeys(log, keys)
	require.Error(t, err)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0,
		Dir:            IPSecDirIn,
		SourceSubnet:   local,
		DestSubnet:     remote,
		SourceTunnelIP: &local.IP,
		DestTunnelIP:   &remote.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.Error(t, err)
}

func TestLoadKeys(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	testCases := [][]byte{keysDat, keysAeadDat, keysAeadDat256}
	for _, testCase := range testCases {
		keys := bytes.NewReader(testCase)
		_, spi, err := LoadIPSecKeys(log, keys)
		require.NoError(t, err)
		err = SetIPSecSPI(log, spi)
		require.NoError(t, err)
	}
}

func TestLoadKeysSameSPI(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	keys := bytes.NewReader(keysSameSpiDat)
	_, _, err := LoadIPSecKeys(log, keys)
	require.ErrorContains(t, err, "invalid SPI: changing IPSec keys requires incrementing the key id")
}

func TestParseSPI(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	testCases := []struct {
		input    string
		expSPI   uint8
		expOff   int
		expESN   bool
		expError bool
	}{
		{"254", 0, 0, false, true},
		{"15", 15, 0, false, false},
		{"3+", 3, 0, true, false},
		{"abc", 0, 0, false, true},
		{"0", 0, 0, false, true},
	}
	for _, tc := range testCases {
		spi, off, esn, err := parseSPI(log, tc.input)
		if spi != tc.expSPI {
			t.Fatalf("For input %q, expected SPI %d, but got %d", tc.input, tc.expSPI, spi)
		}
		if off != tc.expOff {
			t.Fatalf("For input %q, expected base offset %d, but got %d", tc.input, tc.expOff, off)
		}
		if esn != tc.expESN {
			t.Fatalf("For input %q, expected ESN %t, but got %t", tc.input, tc.expESN, esn)
		}
		if tc.expError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestUpsertIPSecEquals(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0,
		Dir:            IPSecDirIn,
		SourceSubnet:   local,
		DestSubnet:     remote,
		SourceTunnelIP: &local.IP,
		DestTunnelIP:   &remote.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	// Let's check that state was not added as source and destination are the same
	result, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Empty(t, result)

	err = DeleteXFRM(log, AllReqID)
	require.NoError(t, err)

	_, aeadKey, err := decodeIPSecKey("44434241343332312423222114131211f4f3f2f1")
	require.NoError(t, err)
	key = &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Aead:  &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: aeadKey, ICVLen: 128},
		Crypt: nil,
		Auth:  nil,
	}

	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	// Let's check that state was not added as source and destination are the same
	result, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Empty(t, result)
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
func TestUpsertIPSecEndpointOut(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
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

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	encryptionMark := generateEncryptMark(key.Spi, params.RemoteNodeID)

	// Confirm state was created with correct marks.
	getState := &netlink.XfrmState{
		Src:   local.IP,
		Dst:   remote.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark:  encryptionMark}

	state, err := netlink.XfrmStateGet(getState)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Nil(t, state.Aead)
	require.NotNil(t, state.Auth)
	require.Equal(t, "hmac(sha256)", state.Auth.Name)
	require.Equal(t, authKey, state.Auth.Key)
	require.NotNil(t, state.Crypt)
	require.Equal(t, "cbc(aes)", state.Crypt.Name)
	require.Equal(t, cryptKey, state.Crypt.Key)
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
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src:   local,
		Dst:   remote,
		Dir:   netlink.XFRM_DIR_OUT,
		Mark:  generateEncryptMark(key.Spi, params.RemoteNodeID),
		Tmpls: tmpls,
	})
	require.NoError(t, err)
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
func TestUpsertIPSecEndpointFwd(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirFwd,
		SourceSubnet:   wildcardCIDRv4,
		DestSubnet:     wildcardCIDRv4,
		SourceTunnelIP: &net.IP{},
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		Optional:       true,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

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
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src:   wildcardCIDRv4,
		Dst:   wildcardCIDRv4,
		Dir:   netlink.XFRM_DIR_FWD,
		Tmpls: tmpls,
	})
	require.NoError(t, err)
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
	if !policyTmpl.Dst.Equal(local.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", local.IP.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, params.ReqID, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)
	require.Equal(t, 1, policyTmpl.Optional)
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
func TestUpsertIPSecEndpointIn(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirIn,
		SourceSubnet:   remote,
		DestSubnet:     local,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	// Confirm state was created with correct marks.
	getState := &netlink.XfrmState{
		Src:   remote.IP,
		Dst:   local.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark:  generateDecryptMark(linux_defaults.RouteMarkDecrypt, params.RemoteNodeID)}

	state, err := netlink.XfrmStateGet(getState)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Nil(t, state.Aead)
	require.NotNil(t, state.Auth)
	require.Equal(t, "hmac(sha256)", state.Auth.Name)
	require.Equal(t, authKey, state.Auth.Key)
	require.NotNil(t, state.Crypt)
	require.Equal(t, "cbc(aes)", state.Crypt.Name)
	require.Equal(t, cryptKey, state.Crypt.Key)
	// ESN bit is not set, so ReplayWindow should be 0
	require.Equal(t, 0, state.ReplayWindow)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:   remote.IP,
			Dst:   local.IP,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: params.ReqID,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src: remote,
		Dst: local,
		Dir: netlink.XFRM_DIR_IN,
		Mark: &netlink.XfrmMark{
			Mask:  linux_defaults.IPsecMarkBitMask,
			Value: linux_defaults.RouteMarkDecrypt,
		},
		Tmpls: tmpls,
	})
	require.NoError(t, err)
	require.NotNil(t, policy)

	// ensure XFRM policy is as we want it...
	if !policy.Src.IP.Equal(remote.IP) {
		t.Fatalf("Expected Src to be %s, but got %s", remote.IP.String(), policy.Src.IP.String())
	}
	if !policy.Dst.IP.Equal(local.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", local.IP.String(), policy.Dst.IP.String())
	}
	require.Equal(t, netlink.XFRM_DIR_IN, policy.Dir)
	require.Equal(t, uint32(linux_defaults.RouteMarkDecrypt), policy.Mark.Value)
	require.Equal(t, uint32(linux_defaults.IPsecMarkBitMask), policy.Mark.Mask)
	require.Len(t, policy.Tmpls, 1)

	// ensure the template is correct as well...
	policyTmpl := policy.Tmpls[0]
	if !policyTmpl.Src.Equal(remote.IP) {
		t.Fatalf("Expected Src to be %s, but got %s", remote.IP.String(), policyTmpl.Src.String())
	}
	if !policyTmpl.Dst.Equal(local.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", local.IP.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, params.ReqID, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)

	// Confirm a policy was created for L7 traffic as well...
	tmpls = []netlink.XfrmPolicyTmpl{
		{
			Src:   remote.IP,
			Dst:   local.IP,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: params.ReqID,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy, err = netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src: remote,
		Dst: local,
		Dir: netlink.XFRM_DIR_IN,
		Mark: &netlink.XfrmMark{
			Mask:  linux_defaults.IPsecMarkBitMask,
			Value: linux_defaults.RouteMarkToProxy,
		},
		Tmpls: tmpls,
	})
	require.NoError(t, err)
	require.NotNil(t, policy)

	// ensure XFRM policy is as we want it...
	if !policy.Src.IP.Equal(remote.IP) {
		t.Fatalf("Expected Src to be %s, but got %s", remote.IP.String(), policy.Src.IP.String())
	}
	if !policy.Dst.IP.Equal(local.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", local.IP.String(), policy.Dst.IP.String())
	}
	require.Equal(t, netlink.XFRM_DIR_IN, policy.Dir)
	require.Equal(t, uint32(linux_defaults.RouteMarkToProxy), policy.Mark.Value)
	require.Equal(t, uint32(linux_defaults.IPsecMarkBitMask), policy.Mark.Mask)
	require.Len(t, policy.Tmpls, 1)

	// ensure the template is correct as well...
	policyTmpl = policy.Tmpls[0]
	// l7 proxy policy has a wildcard source
	if !policyTmpl.Src.Equal(wildcardIPv4) {
		t.Fatalf("Expected Src to be %s, but got %s", remote.IP.String(), policyTmpl.Src.String())
	}
	if !policyTmpl.Dst.Equal(local.IP) {
		t.Fatalf("Expected Dst to be %s, but got %s", local.IP.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, params.ReqID, policyTmpl.Reqid)
	require.Equal(t, netlink.XFRM_MODE_TUNNEL, policyTmpl.Mode)
}

func TestUpsertIPSecKeyMissing(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0,
		Dir:            IPSecDirIn,
		SourceSubnet:   remote,
		DestSubnet:     local,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.ErrorContains(t, err, "unable to replace local state: IPSec key missing")
}

func TestUpdateExistingIPSecEndpoint(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirIn,
		SourceSubnet:   remote,
		DestSubnet:     local,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	// test updateExisting (xfrm delete + add)
	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)
}

func TestZeroPolicyMarkIn(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirIn,
		SourceSubnet:   remote,
		DestSubnet:     local,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		ZeroPolicyMark: true,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	getState := &netlink.XfrmState{
		Src:   remote.IP,
		Dst:   local.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark:  generateDecryptMark(linux_defaults.RouteMarkDecrypt, params.RemoteNodeID)}

	state, err := netlink.XfrmStateGet(getState)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Nil(t, state.Aead)
	require.NotNil(t, state.Auth)
	require.Equal(t, "hmac(sha256)", state.Auth.Name)
	require.Equal(t, authKey, state.Auth.Key)
	require.NotNil(t, state.Crypt)
	require.Equal(t, "cbc(aes)", state.Crypt.Name)
	require.Equal(t, cryptKey, state.Crypt.Key)
	// ESN bit is not set, so ReplayWindow should be 0
	require.Equal(t, 0, state.ReplayWindow)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:   remote.IP,
			Dst:   local.IP,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: params.ReqID,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src:   remote,
		Dst:   local,
		Dir:   netlink.XFRM_DIR_IN,
		Mark:  &netlink.XfrmMark{},
		Tmpls: tmpls,
	})
	require.NoError(t, err)
	require.NotNil(t, policy)

	// test that the mark is set to zero
	require.Equal(t, *policy.Mark, netlink.XfrmMark{
		Value: 0,
		Mask:  0xffffffff,
	})
}

func TestZeroPolicyMarkOut(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

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

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
		LocalBootID:    "local-boot-id",
		RemoteBootID:   "remote-boot-id",
		RemoteNodeID:   0xBEEF,
		Dir:            IPSecDirOut,
		SourceSubnet:   remote,
		DestSubnet:     local,
		SourceTunnelIP: &remote.IP,
		DestTunnelIP:   &local.IP,
		ZeroOutputMark: false,
		ZeroPolicyMark: true,
		RemoteRebooted: false,
		ReqID:          DefaultReqID,
	}

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	tmpls := []netlink.XfrmPolicyTmpl{
		{
			Src:   remote.IP,
			Dst:   local.IP,
			Proto: netlink.XFRM_PROTO_ESP,
			Reqid: params.ReqID,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		},
	}
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src:   remote,
		Dst:   local,
		Dir:   netlink.XFRM_DIR_OUT,
		Mark:  &netlink.XfrmMark{},
		Tmpls: tmpls,
	})
	require.NoError(t, err)
	require.NotNil(t, policy)

	// test that the mark is set to zero
	require.Equal(t, *policy.Mark, netlink.XfrmMark{
		Value: 0,
		Mask:  0xffffffff,
	})
}
