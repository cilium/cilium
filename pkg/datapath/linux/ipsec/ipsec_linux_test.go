// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build privileged_tests

package ipsec

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"

	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IPSecSuitePrivileged struct{}

var _ = Suite(&IPSecSuitePrivileged{})

var (
	path           = "ipsec_keys_test"
	keysDat        = []byte("1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef\n1 hmac(sha256) 0123456789abcdef0123456789abcdef cbc(aes) 0123456789abcdef0123456789abcdef foobar\n1 digest_null \"\" cipher_null \"\"\n")
	keysAeadDat    = []byte("6 rfc4106(gcm(aes)) 44434241343332312423222114131211f4f3f2f1 128\n")
	invalidKeysDat = []byte("1 test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
)

func (p *IPSecSuitePrivileged) SetUpTest(c *C) {
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
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

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
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

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
	c.Assert(err, IsNil)

	ipsecDeleteXfrmSpi(0)

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

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
	c.Assert(err, IsNil)

	ipsecDeleteXfrmSpi(0)
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

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
	c.Assert(err, IsNil)

	ipsecDeleteXfrmSpi(0)

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

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
	c.Assert(err, IsNil)

	ipsecDeleteXfrmSpi(0)
	ipSecKeysGlobal["1.1.3.4"] = nil
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecKeyMissing(c *C) {
	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	_, err = UpsertIPsecEndpoint(local, remote, IPSecDirBoth)
	c.Assert(err, ErrorMatches, "unable to replace local state: IPSec key missing")

	ipsecDeleteXfrmSpi(0)
}
