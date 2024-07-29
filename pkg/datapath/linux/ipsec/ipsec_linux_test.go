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
		ipSecKeysGlobal = make(map[string]*ipSecKey)
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
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n1 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	keysAeadDat256 = []byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f144434241343332312423222114131211 128\n")
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

	testCases := [][]byte{keysDat, keysAeadDat, keysAeadDat256}
	for _, testCase := range testCases {
		keys := bytes.NewReader(testCase)
		_, spi, err := LoadIPSecKeys(log, keys)
		require.NoError(t, err)
		err = SetIPSecSPI(log, spi)
		require.NoError(t, err)
	}
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	// Let's check that state was not added as source and destination are the same
	result, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 0, len(result))

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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	// Let's check that state was not added as source and destination are the same
	result, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err)
	require.Equal(t, 0, len(result))
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

	getState := &netlink.XfrmState{
		Src:   local.IP,
		Dst:   remote.IP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(key.Spi),
		Mark: &netlink.XfrmMark{
			Value: ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, uint8(key.Spi)),
			Mask:  linux_defaults.IPsecMarkMaskOut,
		},
	}

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
}

func TestUpsertIPSecKeyMissing(t *testing.T) {
	log := setupIPSecSuitePrivileged(t)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	require.NoError(t, err)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	require.NoError(t, err)

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
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

	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, false, DefaultReqID)
	require.NoError(t, err)

	// test updateExisting (xfrm delete + add)
	_, err = UpsertIPsecEndpoint(log, local, remote, local.IP, remote.IP, 0, "remote-boot-id", IPSecDirBoth, false, true, DefaultReqID)
	require.NoError(t, err)
}
