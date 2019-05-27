// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package types

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type CNITypesSuite struct{}

var _ = check.Suite(&CNITypesSuite{})

func testConfRead(c *check.C, confContent string, netconf *NetConf) {
	dir, err := ioutil.TempDir("", "cilium-cnitype-testsuite")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "conf1")
	err = ioutil.WriteFile(p, []byte(confContent), 0644)
	c.Assert(err, check.IsNil)

	netConf, _, err := ReadNetConf(p)
	c.Assert(err, check.IsNil)

	c.Assert(netConf, checker.DeepEquals, netconf)
}

func (t *CNITypesSuite) TestReadCNIConf(c *check.C) {
	confFile1 := `
{
  "name": "cilium",
  "type": "cilium-cni"
}
`

	netConf1 := NetConf{
		NetConf: cnitypes.NetConf{
			Name: "cilium",
			Type: "cilium-cni",
		},
	}
	testConfRead(c, confFile1, &netConf1)

	confFile2 := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "mtu": 9000
}
`

	netConf2 := NetConf{
		NetConf: cnitypes.NetConf{
			Name: "cilium",
			Type: "cilium-cni",
		},
		MTU: 9000,
	}
	testConfRead(c, confFile2, &netConf2)
}

func (t *CNITypesSuite) TestReadCNIConfError(c *check.C) {
	// Try to read errorneous CNI configuration file with MTU provided as
	// string instead of int
	errorConf := `
{
  "name": "cilium",
  "type": "cilium-cni",
  "mtu": "9000"
}
`

	dir, err := ioutil.TempDir("", "cilium-cnitype-testsuite")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir)

	p := path.Join(dir, "errorconf")
	err = ioutil.WriteFile(p, []byte(errorConf), 0644)
	c.Assert(err, check.IsNil)

	_, _, err = ReadNetConf(p)
	c.Assert(err, check.Not(check.IsNil))
}
