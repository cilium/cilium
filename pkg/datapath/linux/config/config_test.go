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

// +build privileged_tests

package config

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

type ConfigSuite struct{}

func Test(t *testing.T) {
	TestingT(t)
}

var (
	_ = Suite(&ConfigSuite{})

	dummyNodeCfg  = datapath.LocalNodeConfiguration{}
	dummyDevCfg   = testutils.NewTestEndpoint()
	dummyEPCfg    = testutils.NewTestEndpoint()
	ipv4DummyAddr = []byte{192, 0, 2, 3}
	ipv6DummyAddr = []byte{0x20, 0x01, 0xdb, 0x8, 0x0b, 0xad, 0xca, 0xfe, 0x60, 0x0d, 0xbe, 0xe2, 0x0b, 0xad, 0xca, 0xfe}
)

func (s *ConfigSuite) SetUpTest(c *C) {
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
	node.InitDefaultPrefix("")
	node.SetInternalIPv4(ipv4DummyAddr)
	node.SetIPv4Loopback(ipv4DummyAddr)
	node.SetIPv6Loopback(ipv6DummyAddr)
}

func (s *ConfigSuite) TearDownTest(c *C) {
	node.SetInternalIPv4(nil)
	node.SetIPv4Loopback(nil)
	node.SetIPv6Loopback(nil)
}

type badWriter struct{}

func (b *badWriter) Write(p []byte) (int, error) {
	return 0, errors.New("bad write :(")
}

type writeFn func(io.Writer, datapath.ConfigWriter) error

func writeConfig(c *C, header string, write writeFn) {
	tests := []struct {
		description string
		output      io.Writer
		expResult   Checker
	}{
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
		cfg := &HeaderfileWriter{}
		c.Assert(write(test.output, cfg), test.expResult)
	}
}

func (s *ConfigSuite) TestWriteNodeConfig(c *C) {
	writeConfig(c, "node", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNodeConfig(w, &dummyNodeCfg)
	})
}

func (s *ConfigSuite) TestWriteNetdevConfig(c *C) {
	writeConfig(c, "netdev", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNetdevConfig(w, &dummyDevCfg)
	})
}

func (s *ConfigSuite) TestWriteEndpointConfig(c *C) {
	writeConfig(c, "endpoint", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteEndpointConfig(w, &dummyEPCfg)
	})

	// Create copy of config option so that it can be restored at the end of
	// this test. In the future, we'd like to parallelize running unit tests.
	// As it stands, this test would not be ready to parallelize until we
	// remove our dependency on globals (e.g. option.Config).
	oldEnableIPv6 := option.Config.EnableIPv6
	defer func() {
		option.Config.EnableIPv6 = oldEnableIPv6
	}()

	testRun := func(t *testutils.TestEndpoint) ([]byte, map[string]uint32, map[string]string) {
		cfg := &HeaderfileWriter{}
		varSub, stringSub := loader.ELFSubstitutions(t)

		var buf bytes.Buffer
		cfg.writeStaticData(&buf, t)

		return buf.Bytes(), varSub, stringSub
	}

	lxcIPs := []string{"LXC_IP_1", "LXC_IP_2", "LXC_IP_3", "LXC_IP_4"}

	tests := []struct {
		description string
		template    testutils.TestEndpoint // Represents template bpf prog
		endpoint    testutils.TestEndpoint // Represents normal endpoint bpf prog
		preTestRun  func(t *testutils.TestEndpoint, e *testutils.TestEndpoint)
		templateExp bool
		endpointExp bool
	}{
		{
			description: "IPv6 is disabled, endpoint does not have an IPv6 addr",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = false
				t.IPv6 = ipv6DummyAddr // Template bpf prog always has dummy IPv6
				e.IPv6 = nil           // This endpoint does not have an IPv6 addr
			},
			templateExp: true,
			endpointExp: false,
		},
		{
			description: "IPv6 is disabled, endpoint does have an IPv6 addr",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = false
				t.IPv6 = ipv6DummyAddr // Template bpf prog always has dummy IPv6
				e.IPv6 = ipv6DummyAddr // This endpoint does have an IPv6 addr
			},
			templateExp: true,
			endpointExp: true,
		},
		{
			description: "IPv6 is enabled",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = true
				t.IPv6 = ipv6DummyAddr
				e.IPv6 = ipv6DummyAddr
			},
			templateExp: true,
			endpointExp: true,
		},
		{
			description: "IPv6 is enabled, endpoint does not have IPv6 address",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = true
				t.IPv6 = ipv6DummyAddr
				e.IPv6 = nil
			},
			templateExp: true,
			endpointExp: false,
		},
	}
	for _, test := range tests {
		c.Logf("Testing %s", test.description)
		test.preTestRun(&test.template, &test.endpoint)

		b, vsub, _ := testRun(&test.template)
		c.Assert(bytes.Contains(b, []byte("DEFINE_IPV6")), Equals, test.templateExp)
		assertKeysInsideMap(c, vsub, lxcIPs, test.templateExp)

		b, vsub, _ = testRun(&test.endpoint)
		c.Assert(bytes.Contains(b, []byte("DEFINE_IPV6")), Equals, test.endpointExp)
		assertKeysInsideMap(c, vsub, lxcIPs, test.endpointExp)
	}
}

func (s *ConfigSuite) TestWriteStaticData(c *C) {
	cfg := &HeaderfileWriter{}
	ep := &dummyEPCfg

	varSub, stringSub := loader.ELFSubstitutions(ep)

	var buf bytes.Buffer
	cfg.writeStaticData(&buf, ep)
	b := buf.Bytes()
	for k := range varSub {
		for _, suffix := range []string{"_1", "_2", "_3", "_4"} {
			// Variables with these suffixes are implemented via
			// multiple 32-bit values. The header define doesn't
			// include these numbers though, so strip them.
			if strings.HasSuffix(k, suffix) {
				k = strings.TrimSuffix(k, suffix)
				break
			}
		}
		c.Assert(bytes.Contains(b, []byte(k)), Equals, true)
	}
	for _, v := range stringSub {
		c.Logf("Ensuring config has %s", v)
		if strings.HasPrefix(v, "1/0x") {
			// Skip tail call map name replacement
			continue
		}
		c.Assert(bytes.Contains(b, []byte(v)), Equals, true)
	}
}

func assertKeysInsideMap(c *C, m map[string]uint32, keys []string, want bool) {
	for _, v := range keys {
		_, ok := m[v]
		c.Assert(ok, Equals, want)
	}
}
