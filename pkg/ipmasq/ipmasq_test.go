// Copyright 2020 Authors of Cilium
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

package ipmasq

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/controller"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ipMasqMapMock struct {
	cidrs map[string]net.IPNet
}

func (m *ipMasqMapMock) Update(cidr net.IPNet) error {
	cidrStr := cidr.String()
	if _, ok := m.cidrs[cidrStr]; ok {
		return fmt.Errorf("CIDR already exists: %s", cidrStr)
	}
	m.cidrs[cidrStr] = cidr
	return nil
}

func (m *ipMasqMapMock) Delete(cidr net.IPNet) error {
	cidrStr := cidr.String()
	if _, ok := m.cidrs[cidrStr]; !ok {
		return fmt.Errorf("CIDR not found: %s", cidrStr)
	}
	delete(m.cidrs, cidrStr)
	return nil
}

func (m *ipMasqMapMock) Dump() ([]net.IPNet, error) {
	cidrs := make([]net.IPNet, 0, len(m.cidrs))
	for _, cidr := range m.cidrs {
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}

type IPMasqTestSuite struct {
	ipMasqMap  *ipMasqMapMock
	manager    *controller.Manager
	configFile *os.File
}

var _ = check.Suite(&IPMasqTestSuite{})

func (i *IPMasqTestSuite) SetUpTest(c *check.C) {
	i.ipMasqMap = &ipMasqMapMock{cidrs: map[string]net.IPNet{}}
	i.manager = controller.NewManager()

	configFile, err := ioutil.TempFile("", "ipmasq-test")
	c.Assert(err, check.IsNil)
	i.configFile = configFile

	err = start(configFile.Name(), 100*time.Millisecond, i.ipMasqMap, i.manager)
	c.Assert(err, check.IsNil)
}

func (i *IPMasqTestSuite) TearDownTest(c *check.C) {
	err := i.manager.RemoveController("ip-masq-agent")
	c.Assert(err, check.IsNil)

	os.Remove(i.configFile.Name())
}

func (i *IPMasqTestSuite) TestUpdate(c *check.C) {
	_, err := i.configFile.WriteString("nonMasqueradeCIDRs:\n- 1.1.1.1/32\n- 2.2.2.2/16")
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)

	c.Assert(len(i.ipMasqMap.cidrs), check.Equals, 2)
	_, ok := i.ipMasqMap.cidrs["1.1.1.1/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = i.ipMasqMap.cidrs["2.2.0.0/16"]
	c.Assert(ok, check.Equals, true)

	// Write new config
	_, err = i.configFile.Seek(0, 0)
	c.Assert(err, check.IsNil)
	_, err = i.configFile.WriteString("nonMasqueradeCIDRs:\n- 8.8.0.0/16\n- 2.2.2.2/16")
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)

	c.Assert(len(i.ipMasqMap.cidrs), check.Equals, 2)
	_, ok = i.ipMasqMap.cidrs["8.8.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = i.ipMasqMap.cidrs["2.2.0.0/16"]
	c.Assert(ok, check.Equals, true)

	// Delete file, should remove the CIDRs
	err = os.Remove(i.configFile.Name())
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)
	c.Assert(len(i.ipMasqMap.cidrs), check.Equals, 0)
}

func (i *IPMasqTestSuite) TestRestore(c *check.C) {
	err := i.manager.RemoveController("ip-masq-agent")
	c.Assert(err, check.IsNil)

	_, cidr, _ := net.ParseCIDR("3.3.3.0/24")
	i.ipMasqMap.cidrs[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4.4.0.0/16")
	i.ipMasqMap.cidrs[cidr.String()] = *cidr

	_, err = i.configFile.WriteString("nonMasqueradeCIDRs:\n- 4.4.0.0/16")
	c.Assert(err, check.IsNil)

	err = start(i.configFile.Name(), 100*time.Millisecond, i.ipMasqMap, i.manager)
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)

	c.Assert(len(i.ipMasqMap.cidrs), check.Equals, 1)
	_, ok := i.ipMasqMap.cidrs["4.4.0.0/16"]
	c.Assert(ok, check.Equals, true)
}
