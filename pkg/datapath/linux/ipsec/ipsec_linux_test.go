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

	_, local, err = net.ParseCIDR("1.1.3.4/16")
	require.NoError(tb, err)
	_, remote, err = net.ParseCIDR("1.2.3.4/16")
	require.NoError(tb, err)

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

	local  *net.IPNet
	remote *net.IPNet
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

	params := &IPSecParameters{
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

	_, err = UpsertIPsecEndpoint(log, params)
	require.Error(t, err)
}

func TestLoadKeys(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	testCases := [][]byte{keysDat, keysNullDat, keysAeadDat, keysAeadDat256}
	for _, testCase := range testCases {
		keys := bytes.NewReader(testCase)
		_, spi, err := LoadIPSecKeys(log, keys)
		require.NoError(t, err)
		err = SetIPSecSPI(log, spi)
		require.NoError(t, err)
		UnsetTestIPSecKey()
	}
}

func TestLoadKeysLenChange(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	keys := bytes.NewReader(append(keysDat, keysNullDat...))
	_, _, err := LoadIPSecKeys(log, keys)
	require.ErrorContains(t, err, "invalid key rotation: key length must not change")
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
		expError bool
	}{
		{"254", 0, 0, true},
		{"15", 15, 0, false},
		{"3+", 3, 0, false},
		{"abc", 0, 0, true},
		{"0", 0, 0, true},
	}
	for _, tc := range testCases {
		spi, off, err := parseSPI(log, tc.input)
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

func TestUpsertIPSecEquals(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	// Set source and destination to same IP.
	local = remote

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

	ipSecKeysGlobal[remote.IP.String()] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
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

	ipSecKeysGlobal[remote.IP.String()] = key
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

	ipSecKeysGlobal[local.IP.String()] = key
	ipSecKeysGlobal[remote.IP.String()] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
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

	ipSecKeysGlobal[local.IP.String()] = key
	ipSecKeysGlobal[remote.IP.String()] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
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
	if !policyTmpl.Dst.Equal(wildcardIPv4) {
		t.Fatalf("Expected Dst to be %s, but got %s", wildcardIPv4.String(), policyTmpl.Dst.String())
	}
	require.Equal(t, netlink.XFRM_PROTO_ESP, policyTmpl.Proto)
	require.Equal(t, 0, policyTmpl.Reqid)
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

	ipSecKeysGlobal[local.IP.String()] = key
	ipSecKeysGlobal[remote.IP.String()] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
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
	policy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src:   wildcardCIDRv4,
		Dst:   wildcardCIDRv4,
		Dir:   netlink.XFRM_DIR_IN,
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

func TestUpsertIPSecKeyMissing(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	params := &IPSecParameters{
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

	_, err := UpsertIPsecEndpoint(log, params)
	require.ErrorContains(t, err, "unable to replace local state: global IPsec key missing")
}

func TestUpdateExistingIPSecEndpoint(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

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

	ipSecKeysGlobal[local.IP.String()] = key
	ipSecKeysGlobal[remote.IP.String()] = key
	ipSecKeysGlobal[""] = key

	params := &IPSecParameters{
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

	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)

	// test updateExisting (xfrm delete + add)
	_, err = UpsertIPsecEndpoint(log, params)
	require.NoError(t, err)
}
