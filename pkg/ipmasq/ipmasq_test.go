// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
)

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

func setUpTest(tb testing.TB) *IPMasqTestSuite {
	i := &IPMasqTestSuite{}
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv4: map[string]net.IPNet{},
		cidrsIPv6: map[string]net.IPNet{},
	}

	configFile, err := os.CreateTemp("", "ipmasq-test")
	require.NoError(tb, err)
	i.configFilePath = configFile.Name()

	agent, err := newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(tb, err)
	i.ipMasqAgent = agent

	tb.Cleanup(func() {
		i.ipMasqAgent.Stop()
		os.Remove(i.configFilePath)
	})

	return i
}

func (i *IPMasqTestSuite) writeConfig(t *testing.T, cfg string) {
	err := os.WriteFile(i.configFilePath, []byte(cfg), 0644)
	require.NoError(t, err)
}

func TestUpdateIPv4(t *testing.T) {
	i := setUpTest(t)

	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = false
	i.ipMasqAgent.Start()
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 1.1.1.1/32\n- 2.2.2.2/16")
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 3)
	_, ok := ipnets["1.1.1.1/32"]
	require.True(t, ok)
	_, ok = ipnets["2.2.0.0/16"]
	require.True(t, ok)

	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)

	// Write new config
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 8.8.0.0/16\n- 2.2.2.2/16")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 3)
	_, ok = ipnets["8.8.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets["2.2.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)

	// Write config with no CIDRs
	i.writeConfig(t, "nonMasqueradeCIDRs:\n")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 1)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)

	// Write new config in JSON
	i.writeConfig(t, `{"nonMasqueradeCIDRs": ["8.8.0.0/16", "1.1.2.3/16"], "masqLinkLocal": true}`)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok = ipnets["8.8.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets["1.1.0.0/16"]
	require.True(t, ok)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, len(defaultNonMasqCIDRs)+1)
	for cidrStr := range defaultNonMasqCIDRs {
		_, ok := ipnets[cidrStr]
		require.True(t, ok)
	}
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
}

func TestUpdateIPv6(t *testing.T) {
	i := setUpTest(t)

	i.ipMasqMap.ipv4Enabled = false
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 1:1:1:1::/64\n- 2:2::/32")
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 3)
	_, ok := ipnets["1:1:1:1::/64"]
	require.True(t, ok)
	_, ok = ipnets["2:2::/32"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write new config
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 8:8:8:8::/64\n- 2:2::/32")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 3)
	_, ok = ipnets["8:8:8:8::/64"]
	require.True(t, ok)
	_, ok = ipnets["2:2::/32"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write config with no CIDRs
	i.writeConfig(t, "nonMasqueradeCIDRs:\n")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 1)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write new config in JSON
	i.writeConfig(t, `{"nonMasqueradeCIDRs": ["8:8:8:8::/64", "1:2:3:4::/64"], "masqLinkLocalIPv6": true}`)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok = ipnets["8:8:8:8::/64"]
	require.True(t, ok)
	_, ok = ipnets["1:2:3:4::/64"]
	require.True(t, ok)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 1)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)
}

func TestUpdate(t *testing.T) {
	i := setUpTest(t)
	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 1.1.1.1/32\n- 2:2::/32")
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 4)
	_, ok := ipnets["1.1.1.1/32"]
	require.True(t, ok)
	_, ok = ipnets["2:2::/32"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write new config
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 8:8:8:8::/64\n- 2.2.0.0/16")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 4)
	_, ok = ipnets["8:8:8:8::/64"]
	require.True(t, ok)
	_, ok = ipnets["2.2.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write config with no CIDRs
	i.writeConfig(t, "nonMasqueradeCIDRs:\n")
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Write new config in JSON
	i.writeConfig(t, `{"nonMasqueradeCIDRs": ["1.2.3.4/32", "1:2:3:4::/64"], "masqLinkLocalIPv6": true}`)
	time.Sleep(300 * time.Millisecond)

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 3)
	_, ok = ipnets["1.2.3.4/32"]
	require.True(t, ok)
	_, ok = ipnets["1:2:3:4::/64"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)

	// Delete file, should remove the CIDRs and add default nonMasq CIDRs
	err := os.Remove(i.configFilePath)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, len(defaultNonMasqCIDRs)+1+1)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)
}

func TestRestoreIPv4(t *testing.T) {
	var err error

	i := setUpTest(t)
	i.ipMasqMap.ipv4Enabled = true
	i.ipMasqMap.ipv6Enabled = false
	i.ipMasqAgent.Start()
	// Check that stale entry is removed from the map after restore
	i.ipMasqAgent.Stop()

	_, cidr, _ := net.ParseCIDR("3.3.3.0/24")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4.4.0.0/16")
	i.ipMasqMap.cidrsIPv4[cidr.String()] = *cidr
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 4.4.0.0/16")

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok := ipnets["4.4.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)

	// Now stop the goroutine, and also remove the maps. It should bootstrap from
	// the config
	i.ipMasqAgent.Stop()
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv4:   map[string]net.IPNet{},
		ipv4Enabled: true,
		ipv6Enabled: false,
	}
	i.ipMasqAgent.ipMasqMap = i.ipMasqMap
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 3.3.0.0/16\nmasqLinkLocal: true")
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 1)
	_, ok = ipnets["3.3.0.0/16"]
	require.True(t, ok)
}

func TestRestoreIPv6(t *testing.T) {
	var err error

	i := setUpTest(t)
	i.ipMasqMap.ipv4Enabled = false
	i.ipMasqMap.ipv6Enabled = true
	i.ipMasqAgent.Start()
	// Check that stale entry is removed from the map after restore
	i.ipMasqAgent.Stop()

	_, cidr, _ := net.ParseCIDR("3:3:3:3::/64")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	_, cidr, _ = net.ParseCIDR("4:4::/32")
	i.ipMasqMap.cidrsIPv6[cidr.String()] = *cidr
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 4:4::/32")

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok := ipnets["4:4::/32"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

	// Now stop the goroutine, and also remove the maps. It should bootstrap from
	// the config
	i.ipMasqAgent.Stop()
	i.ipMasqMap = &ipMasqMapMock{
		cidrsIPv6:   map[string]net.IPNet{},
		ipv4Enabled: false,
		ipv6Enabled: true,
	}
	i.ipMasqAgent.ipMasqMap = i.ipMasqMap
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 3:3::/96\nmasqLinkLocalIPv6: true")
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 1)
	_, ok = ipnets["3:3::/96"]
	require.True(t, ok)
}

func TestRestore(t *testing.T) {
	var err error

	i := setUpTest(t)
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
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 4.4.0.0/16\n- 4:4::/32")

	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()
	time.Sleep(300 * time.Millisecond)

	ipnets := i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 4)
	_, ok := ipnets["4.4.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets["4:4::/32"]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv4Str]
	require.True(t, ok)
	_, ok = ipnets[linkLocalCIDRIPv6Str]
	require.True(t, ok)

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
	i.writeConfig(t, "nonMasqueradeCIDRs:\n- 3.3.0.0/16\n- 3:3:3:3::/96\nmasqLinkLocal: true\nmasqLinkLocalIPv6: true")
	i.ipMasqAgent, err = newIPMasqAgent(i.configFilePath, i.ipMasqMap)
	require.NoError(t, err)
	i.ipMasqAgent.Start()

	ipnets = i.ipMasqMap.dumpToSet()
	require.Len(t, ipnets, 2)
	_, ok = ipnets["3.3.0.0/16"]
	require.True(t, ok)
	_, ok = ipnets["3:3:3:3::/96"]
	require.True(t, ok)
}
