// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ipMasqMapMock struct {
	lock.RWMutex
	ipv4Enabled bool
	ipv6Enabled bool
	cidrsIPv4   map[string]net.IPNet
	cidrsIPv6   map[string]net.IPNet
}

func (m *ipMasqMapMock) Update(cidr net.IPNet) error {
	m.Lock()
	defer m.Unlock()

	cidrStr := cidr.String()
	if ip.IsIPv4(cidr.IP) {
		if m.ipv4Enabled {
			if _, ok := m.cidrsIPv4[cidrStr]; ok {
				return fmt.Errorf("CIDR already exists: %s", cidrStr)
			}
			m.cidrsIPv4[cidrStr] = cidr
		} else {
			return fmt.Errorf("IPv4 disabled, but required for this CIDR: %s", cidrStr)
		}
	} else {
		if m.ipv6Enabled {
			if _, ok := m.cidrsIPv6[cidrStr]; ok {
				return fmt.Errorf("CIDR already exists: %s", cidrStr)
			}
			m.cidrsIPv6[cidrStr] = cidr
		} else {
			return fmt.Errorf("IPv6 disabled, but required for this CIDR: %s", cidrStr)
		}
	}

	return nil
}

func (m *ipMasqMapMock) Delete(cidr net.IPNet) error {
	m.Lock()
	defer m.Unlock()

	cidrStr := cidr.String()
	if ip.IsIPv4(cidr.IP) {
		if m.ipv4Enabled {
			if _, ok := m.cidrsIPv4[cidrStr]; !ok {
				return fmt.Errorf("CIDR not found: %s", cidrStr)
			}
			delete(m.cidrsIPv4, cidrStr)
		} else {
			return fmt.Errorf("IPv4 disabled, but required for this CIDR: %s", cidrStr)
		}
	} else {
		if m.ipv6Enabled {
			if _, ok := m.cidrsIPv6[cidrStr]; !ok {
				return fmt.Errorf("CIDR not found: %s", cidrStr)
			}
			delete(m.cidrsIPv6, cidrStr)
		} else {
			return fmt.Errorf("IPv6 disabled, but required for this CIDR: %s", cidrStr)
		}
	}

	return nil
}

func (m *ipMasqMapMock) Dump() ([]net.IPNet, error) {
	m.RLock()
	defer m.RUnlock()

	cidrs := make([]net.IPNet, 0, len(m.cidrsIPv4)+len(m.cidrsIPv6))
	if m.ipv4Enabled {
		for _, cidr := range m.cidrsIPv4 {
			cidrs = append(cidrs, cidr)
		}
	}
	if m.ipv6Enabled {
		for _, cidr := range m.cidrsIPv6 {
			cidrs = append(cidrs, cidr)
		}
	}

	return cidrs, nil
}

func (m *ipMasqMapMock) dumpToSet() map[string]struct{} {
	m.RLock()
	defer m.RUnlock()

	length := 0
	if m.ipv4Enabled {
		length += len(m.cidrsIPv4)
	}
	if m.ipv6Enabled {
		length += len(m.cidrsIPv6)
	}

	cidrs := make(map[string]struct{}, length)
	if m.ipv4Enabled {
		for cidrStr := range m.cidrsIPv4 {
			cidrs[cidrStr] = struct{}{}
		}
	}
	if m.ipv6Enabled {
		for cidrStr := range m.cidrsIPv6 {
			cidrs[cidrStr] = struct{}{}
		}
	}

	return cidrs
}

type IPMasqTestSuite struct {
	ipMasqMap      *ipMasqMapMock
	ipMasqAgent    *IPMasqAgent
	configFilePath string
}

var _ = check.Suite(&IPMasqTestSuite{})

func (i *IPMasqTestSuite) SetUpTest(c *check.C) {
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv4: map[string]net.IPNet{},
		cidrsIPv6: map[string]net.IPNet{},
	}

	configFile, err := os.CreateTemp("", "ipmasq-test")
	c.Assert(err, check.IsNil)
	i.configFilePath = configFile.Name()

	agent, err := newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent = agent
}

func (i *IPMasqTestSuite) TearDownTest(c *check.C) {
	i.ipMasqAgent.Stop()
	os.Remove(i.configFilePath)
}

func (i *IPMasqTestSuite) writeConfig(cfg string, c *check.C) {
	err := os.WriteFile(i.configFilePath, []byte(cfg), 0644)
	c.Assert(err, check.IsNil)
}

func (i *IPMasqTestSuite) TestUpdateIPv4(c *check.C) {
	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = false
	i.ipMasqAgent.Start()
	i.writeConfig("nonMasqueradeCIDRs:\n- 1.1.1.1/32\n- 2.2.2.2/16", c)
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 3)
	_, ok := ipnets["1.1.1.1/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2.2.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)

	// Write new config
	i.writeConfig("nonMasqueradeCIDRs:\n- 8.8.0.0/16\n- 2.2.2.2/16", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 3)
	_, ok = ipnets["8.8.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2.2.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)

	// Write config with no CIDRs
	i.writeConfig("nonMasqueradeCIDRs:\n", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 1)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)

	// Write new config in JSON
	i.writeConfig(`{"nonMasqueradeCIDRs": ["8.8.0.0/16", "1.1.2.3/16"], "masqLinkLocal": true}`, c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok = ipnets["8.8.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["1.1.0.0/16"]
	c.Assert(ok, check.Equals, true)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, len(defaultNonMasqCIDRs)+1)
	for cidrStr := range defaultNonMasqCIDRs {
		_, ok := ipnets[cidrStr]
		c.Assert(ok, check.Equals, true)
	}
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
}

func (i *IPMasqTestSuite) TestUpdateIPv6(c *check.C) {
	i.ipMasqMap.ipv4Enabled = false
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	i.writeConfig("nonMasqueradeCIDRs:\n- 1:1:1:1::/64\n- 2:2::/32", c)
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 3)
	_, ok := ipnets["1:1:1:1::/64"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2:2::/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write new config
	i.writeConfig("nonMasqueradeCIDRs:\n- 8:8:8:8::/64\n- 2:2::/32", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 3)
	_, ok = ipnets["8:8:8:8::/64"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2:2::/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write config with no CIDRs
	i.writeConfig("nonMasqueradeCIDRs:\n", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 1)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write new config in JSON
	i.writeConfig(`{"nonMasqueradeCIDRs": ["8:8:8:8::/64", "1:2:3:4::/64"], "masqLinkLocalIPv6": true}`, c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok = ipnets["8:8:8:8::/64"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["1:2:3:4::/64"]
	c.Assert(ok, check.Equals, true)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 1)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)
}

func (i *IPMasqTestSuite) TestUpdate(c *check.C) {
	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	i.writeConfig("nonMasqueradeCIDRs:\n- 1.1.1.1/32\n- 2:2::/32", c)
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 4)
	_, ok := ipnets["1.1.1.1/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2:2::/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write new config
	i.writeConfig("nonMasqueradeCIDRs:\n- 8:8:8:8::/64\n- 2.2.0.0/16", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 4)
	_, ok = ipnets["8:8:8:8::/64"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["2.2.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write config with no CIDRs
	i.writeConfig("nonMasqueradeCIDRs:\n", c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Write new config in JSON
	i.writeConfig(`{"nonMasqueradeCIDRs": ["1.2.3.4/32", "1:2:3:4::/64"], "masqLinkLocalIPv6": true}`, c)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 3)
	_, ok = ipnets["1.2.3.4/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["1:2:3:4::/64"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	c.Assert(err, check.IsNil)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, len(defaultNonMasqCIDRs)+1+1)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)
}

func (i *IPMasqTestSuite) TestRestoreIPv4(c *check.C) {
	var err error

	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = false
	i.ipMasqAgent.Start()
	// Check that stale entry is removed from the map after restore
	i.ipMasqAgent.Stop()

	_, cidr, _ := net.ParseCIDR("3.3.3.0/24")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4.4.0.0/16")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	i.writeConfig("nonMasqueradeCIDRs:\n- 4.4.0.0/16", c)

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok := ipnets["4.4.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)

	// Now stop the goroutine, and also remove the maps. It should bootstrap from
	// the config
	i.ipMasqAgent.Stop()
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv4:   map[string]net.IPNet{},
		ipv4Enabled: true,
		ipv6Enabled: false,
	}
	i.ipMasqAgent.ipMasqMap = i.ipMasqMap
	i.writeConfig("nonMasqueradeCIDRs:\n- 3.3.0.0/16\nmasqLinkLocal: true", c)
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 1)
	_, ok = ipnets["3.3.0.0/16"]
	c.Assert(ok, check.Equals, true)
}

func (i *IPMasqTestSuite) TestRestoreIPv6(c *check.C) {
	var err error

	i.ipMasqMap.ipv4Enabled = false
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	// Check that stale entry is removed from the map after restore
	i.ipMasqAgent.Stop()

	_, cidr, _ := net.ParseCIDR("3:3:3:3::/64")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4:4::/32")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	i.writeConfig("nonMasqueradeCIDRs:\n- 4:4::/32", c)

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok := ipnets["4:4::/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Now stop the goroutine, and also remove the maps. It should bootstrap from
	// the config
	i.ipMasqAgent.Stop()
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv6:   map[string]net.IPNet{},
		ipv4Enabled: false,
		ipv6Enabled: true,
	}
	i.ipMasqAgent.ipMasqMap = i.ipMasqMap
	i.writeConfig("nonMasqueradeCIDRs:\n- 3:3::/96\nmasqLinkLocalIPv6: true", c)
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 1)
	_, ok = ipnets["3:3::/96"]
	c.Assert(ok, check.Equals, true)
}

func (i *IPMasqTestSuite) TestRestore(c *check.C) {
	var err error

	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	// Check that stale entry is removed from the map after restore
	i.ipMasqAgent.Stop()

	_, cidr, _ := net.ParseCIDR("3:3:3:3::/64")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4:4::/32")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("3.3.3.0/24")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4.4.0.0/16")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	i.writeConfig("nonMasqueradeCIDRs:\n- 4.4.0.0/16\n- 4:4::/32", c)

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 4)
	_, ok := ipnets["4.4.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["4:4::/32"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	c.Assert(ok, check.Equals, true)

	// Now stop the goroutine, and also remove the maps. It should bootstrap from
	// the config
	i.ipMasqAgent.Stop()
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv4:   map[string]net.IPNet{},
		cidrsIPv6:   map[string]net.IPNet{},
		ipv4Enabled: true,
		ipv6Enabled: true,
	}
	i.ipMasqAgent.ipMasqMap = i.ipMasqMap
	i.writeConfig("nonMasqueradeCIDRs:\n- 3.3.0.0/16\n- 3:3:3:3::/96\nmasqLinkLocal: true\nmasqLinkLocalIPv6: true", c)
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	c.Assert(err, check.IsNil)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	c.Assert(len(ipnets), check.Equals, 2)
	_, ok = ipnets["3.3.0.0/16"]
	c.Assert(ok, check.Equals, true)
	_, ok = ipnets["3:3:3:3::/96"]
	c.Assert(ok, check.Equals, true)
}
