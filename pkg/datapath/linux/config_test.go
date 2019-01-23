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

package linux

import (
	"bytes"
	"errors"
	"io"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

type DatapathSuite struct{}

var (
	_ = Suite(&DatapathSuite{})

	dummyNodeCfg = datapath.LocalNodeConfiguration{}
	dummyDevCfg  = dummyEP{}
	dummyEPCfg   = dummyEP{id: 42}
)

func (s *DatapathSuite) SetUpTest(c *C) {
	node.InitDefaultPrefix("")
}

type badWriter struct{}

func (b *badWriter) Write(p []byte) (int, error) {
	return 0, errors.New("bad write :(")
}

type dummyEP struct {
	id uint64
}

func (d *dummyEP) HasIpvlanDataPath() bool               { return false }
func (d *dummyEP) ConntrackLocalLocked() bool            { return false }
func (d *dummyEP) GetCIDRPrefixLengths() ([]int, []int)  { return nil, nil }
func (d *dummyEP) GetID() uint64                         { return d.id }
func (d *dummyEP) StringID() string                      { return "42" }
func (d *dummyEP) GetIdentity() identity.NumericIdentity { return 42 }
func (d *dummyEP) GetNodeMAC() mac.MAC                   { return nil }

func (d *dummyEP) IPv4Address() addressing.CiliumIPv4 {
	addr, _ := addressing.NewCiliumIPv4("192.0.2.3")
	return addr
}
func (d *dummyEP) IPv6Address() addressing.CiliumIPv6 {
	addr, _ := addressing.NewCiliumIPv6("::ffff:192.0.2.3")
	return addr
}
func (d *dummyEP) GetOptions() *option.IntOptions {
	result := option.NewIntOptions(&option.OptionLibrary{})
	result.SetBool("TEST_OPTION", true)
	return result
}

type testCase struct {
	description string
	output      io.Writer
	expResult   Checker
}

type writeFn func(io.Writer, datapath.Datapath) error

func writeConfig(c *C, header string, write writeFn) {
	tests := []testCase{
		{
			description: "successful write to an in-memory buffer",
			output:      &bytes.Buffer{},
			expResult:   IsNil,
		},
		{
			description: "write to a failing writer",
			output:      &badWriter{},
			expResult:   NotNil,
		},
	}
	for _, test := range tests {
		c.Logf("  Testing %s configuration: %s", header, test.description)
		dp := NewDatapath(DatapathConfiguration{})
		c.Assert(write(test.output, dp), test.expResult)
	}
}

func (s *DatapathSuite) TestWriteNodeConfig(c *C) {
	writeConfig(c, "node", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteNodeConfig(w, &dummyNodeCfg)
	})
}

func (s *DatapathSuite) TestWriteNetdevConfig(c *C) {
	writeConfig(c, "netdev", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteNetdevConfig(w, &dummyDevCfg)
	})
}

func (s *DatapathSuite) TestWriteEndpointConfig(c *C) {
	writeConfig(c, "endpoint", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteEndpointConfig(w, &dummyEPCfg)
	})
}
