// Copyright 2018 Authors of Cilium
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
	"net"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/vishvananda/netlink"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IPSecSuitePrivileged struct{}

var _ = Suite(&IPSecSuitePrivileged{})

var (
	path             = "ipsec_keys_test"
	dflt_keys_dat    = []byte("hmac(sha256) abcdefghijklmnopqrstuvwzyzABCDEF cbc(aes) abcdefghijklmnopqrstuvwzyzABCDEF\n")
	scoped_keys_dat  = []byte("hmac(sha256) abcdefghijklmnopqrstuvwzyzABCDEF cbc(aes) abcdefghijklmnopqrstuvwzyzABCDEF foobar\n")
	invalid_keys_dat = []byte("test abcdefghijklmnopqrstuvwzyzABCDEF test abcdefghijklmnopqrstuvwzyzABCDEF\n")
)

func (p *IPSecSuitePrivileged) TestLoadKeysNoFile(c *C) {
	err := LoadIPSecKeysFile(path)
	c.Assert(err, ErrorMatches, "open ipsec_keys_test: no such file or directory")
}

func (p *IPSecSuitePrivileged) TestInvalidLoadKesyFile(c *C) {
	f, err := os.Create(path)
	c.Assert(err, IsNil)
	defer f.Close()
	_, err = f.Write(invalid_keys_dat)
	c.Assert(err, IsNil)
	f.Sync()
	err = LoadIPSecKeysFile(path)
	c.Assert(err, IsNil)
	err = os.Remove(path)
	c.Assert(err, IsNil)

	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)
	err = UpsertIPSecEndpoint(local, remote)
	c.Assert(err, NotNil)
}

func (p *IPSecSuitePrivileged) TestLoadKesyFile(c *C) {
	path := "ipsec_keys_test"
	f, err := os.Create(path)
	c.Assert(err, IsNil)
	defer f.Close()
	_, err = f.Write(dflt_keys_dat)
	c.Assert(err, IsNil)
	_, err = f.Write(scoped_keys_dat)
	c.Assert(err, IsNil)
	f.Sync()
	err = LoadIPSecKeysFile(path)
	c.Assert(err, IsNil)
	err = os.Remove(path)
	c.Assert(err, IsNil)
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecEquals(c *C) {
	_, local, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: []byte("abcdefghijklmnopqrstuvwzyzABCDEF")},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: []byte("abcdefghijklmnopqrstuvwzyzABCDEF")},
	}

	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	err = UpsertIPSecEndpoint(local, remote)
	c.Assert(err, IsNil)

	err = DeleteIPSecEndpoint(remote.IP, local.IP)
	c.Assert(err, IsNil)

	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil

}

func (p *IPSecSuitePrivileged) TestUpsertIPSecEndpoint(c *C) {
	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	key := &ipSecKey{
		Spi:   1,
		ReqID: 1,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: []byte("abcdefghijklmnopqrstuvwzyzABCDEF")},
		Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: []byte("abcdefghijklmnopqrstuvwzyzABCDEF")},
	}

	ipSecKeysGlobal["1.1.3.4"] = key
	ipSecKeysGlobal["1.2.3.4"] = key
	ipSecKeysGlobal[""] = key

	err = UpsertIPSecEndpoint(local, remote)
	c.Assert(err, IsNil)

	err = DeleteIPSecEndpoint(remote.IP, local.IP)
	c.Assert(err, IsNil)

	ipSecKeysGlobal["1.1.3.4"] = nil
	ipSecKeysGlobal["1.2.3.4"] = nil
	ipSecKeysGlobal[""] = nil
}

func (p *IPSecSuitePrivileged) TestUpsertIPSecKeyMissing(c *C) {
	_, local, err := net.ParseCIDR("1.1.3.4/16")
	c.Assert(err, IsNil)
	_, remote, err := net.ParseCIDR("1.2.3.4/16")
	c.Assert(err, IsNil)

	err = UpsertIPSecEndpoint(local, remote)
	c.Assert(err, ErrorMatches, "IPSec key missing")

	err = DeleteIPSecEndpoint(remote.IP, local.IP)
	c.Assert(err, IsNil)
}
