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
		node.UnsetTestLocalNodeStore()
		_ = DeleteXFRM(log)
	})
	return log
}

var (
	path           = "ipsec_keys_test"
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef foobar\n1 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	invalidKeysDat = []byte("1 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
)

func TestLoadKeysNoFile(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, _, err := LoadIPSecKeysFile(log, path)
	require.Equal(t, true, os.IsNotExist(err))
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.Error(t, err)
}

func TestLoadKeys(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	keys := bytes.NewReader(keysDat)
	_, spi, err := LoadIPSecKeys(log, keys)
	require.NoError(t, err)
	err = SetIPSecSPI(log, spi)
	require.NoError(t, err)
	keys = bytes.NewReader(keysAeadDat)
	_, spi, err = LoadIPSecKeys(log, keys)
	require.NoError(t, err)
	err = SetIPSecSPI(log, spi)
	require.NoError(t, err)
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
		{"abc", 1, -1, false, false},
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	cleanIPSecStatesAndPolicies(t)

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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	cleanIPSecStatesAndPolicies(t)
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func TestUpsertIPSecEndpoint(t *testing.T) {
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	cleanIPSecStatesAndPolicies(t)

	_, aeadKey, err := decodeIPSecKey("44434241343332312423222114131211f4f3f2f1")
	require.NoError(t, err)
	key = &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Aead:  &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: aeadKey, ICVLen: 128},
		Crypt: nil,
		Auth:  nil,
	}

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	// Assert additional rule when tunneling is enabled is inserted
	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)
	toProxyPolicy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src: remote,
		Dst: local,
		Dir: netlink.XFRM_DIR_IN,
		Mark: &netlink.XfrmMark{
			Mask:  linux_defaults.IPsecMarkBitMask,
			Value: linux_defaults.RouteMarkToProxy,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, toProxyPolicy)

	cleanIPSecStatesAndPolicies(t)
	ipSecKeysGlobal["1.1.3.4"] = nil
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func TestUpsertIPSecKeyMissing(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.ErrorContains(t, err, "unable to replace local state: IPSec key missing")

	cleanIPSecStatesAndPolicies(t)
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	// test updateExisting (xfrm delete + add)
	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, true, DefaultReqID)
	require.NoError(t, err)

	cleanIPSecStatesAndPolicies(t)
	ipSecKeysGlobal["1.1.3.4"] = nil
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func cleanIPSecStatesAndPolicies(t *testing.T) {
	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("Can't list XFRM states: %v", err)
	}

	for _, s := range xfrmStateList {
		if err := netlink.XfrmStateDel(&s); err != nil {
			t.Fatalf("Can't delete XFRM state: %v", err)
		}

	}

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("Can't list XFRM policies: %v", err)
	}

	for _, p := range xfrmPolicyList {
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			t.Fatalf("Can't delete XFRM policy: %v", err)
		}
	}
}
