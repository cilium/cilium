// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"bytes"
	"net"
	"os"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IPSecSuitePrivileged struct{}

var _ = Suite(&IPSecSuitePrivileged{})

func (s *IPSecSuitePrivileged) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

var (
	path           = "ipsec_keys_test"
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef foobar\n1 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	invalidKeysDat = []byte("1 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
)

func (p *IPSecSuitePrivileged) SetUpTest(c *C) {
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (p *IPSecSuitePrivileged) TearDownTest(c *C) {
	DeleteXfrm()
}

func (p *IPSecSuitePrivileged) TestLoadKeysNoFile(c *C) {
	_, _, err := LoadIPSecKeysFile(path)
	c.Assert(os.IsNotExist(err), Equals, true)
}

func (p *IPSecSuitePrivileged) TestInvalidLoadKeys(c *C) {
	keys := bytes.NewReader(invalidKeysDat)
	_, _, err := loadIPSecKeys(keys)
	c.Assert(err, NotNil)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, NotNil)
}

func (p *IPSecSuitePrivileged) TestLoadKeys(c *C) {
	keys := bytes.NewReader(keysDat)
	_, _, err := loadIPSecKeys(keys)
	c.Assert(err, IsNil)
	keys = bytes.NewReader(keysAeadDat)
	_, _, err = loadIPSecKeys(keys)
	c.Assert(err, IsNil)
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecEquals(c *C) {
	_, local, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	c.Assert(err, IsNil)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	c.Assert(err, IsNil)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, IsNil)

	cleanIPSecStatesAndPolicies(c)

	_, aeadKey, err := decodeIPSecKey("44434241343332312423222114131211f4f3f2f1")
	c.Assert(err, IsNil)
	key = &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Aead:  &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: aeadKey, ICVLen: 128},
		Crypt: nil,
		Auth:  nil,
	}

	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, IsNil)

	cleanIPSecStatesAndPolicies(c)
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecEndpoint(c *C) {
	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	_, authKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	c.Assert(err, IsNil)
	_, cryptKey, err := decodeIPSecKey("0123456789abcdef0123456789abcdef")
	c.Assert(err, IsNil)
	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: authKey},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: cryptKey},
	}

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, IsNil)

	cleanIPSecStatesAndPolicies(c)

	_, aeadKey, err := decodeIPSecKey("44434241343332312423222114131211f4f3f2f1")
	c.Assert(err, IsNil)
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

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, IsNil)

	// Assert additional rule when tunneling is enabled is inserted
	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, IsNil)
	toProxyPolicy, err := netlink.XfrmPolicyGet(&netlink.XfrmPolicy{
		Src: remote,
		Dst: local,
		Dir: netlink.XFRM_DIR_IN,
		Mark: &netlink.XfrmMark{
			Mask:  linux_defaults.IPsecMarkMaskIn,
			Value: linux_defaults.RouteMarkToProxy,
		},
	})
	c.Assert(err, IsNil)
	c.Assert(toProxyPolicy, Not(IsNil))

	cleanIPSecStatesAndPolicies(c)
	ipSecKeysGlobal["1.1.3.4"] = nil
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecKeyMissing(c *C) {
	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	_, err = UpsertIPsecEndpoint(local, remote, local.IP, remote.IP, 0, IPSecDirBoth, false)
	c.Assert(err, ErrorMatches, "unable to replace local state: IPSec key missing")

	cleanIPSecStatesAndPolicies(c)
}

func cleanIPSecStatesAndPolicies(c *C) {
	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Can't list XFRM states: %v", err)
	}

	for _, s := range xfrmStateList {
		if err := netlink.XfrmStateDel(&s); err != nil {
			c.Fatalf("Can't delete XFRM state: %v", err)
		}

	}

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		c.Fatalf("Can't list XFRM policies: %v", err)
	}

	for _, p := range xfrmPolicyList {
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			c.Fatalf("Can't delete XFRM policy: %v", err)
		}
	}
}
