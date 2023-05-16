// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"errors"
	"fmt"
	"net"
	"os/exec"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/testutils"
)

var _ = Suite(&MigrateSuite{})

type MigrateSuite struct {
	// rpdb interface mock
	OnRuleList func(int) ([]netlink.Rule, error)
	OnRuleAdd  func(*netlink.Rule) error
	OnRuleDel  func(*netlink.Rule) error

	OnRouteListFiltered func(int, *netlink.Route, uint64) ([]netlink.Route, error)
	OnRouteAdd          func(*netlink.Route) error
	OnRouteDel          func(*netlink.Route) error
	OnRouteReplace      func(*netlink.Route) error

	OnLinkList    func() ([]netlink.Link, error)
	OnLinkByIndex func(int) (netlink.Link, error)

	// interfaceDB interface mock
	OnGetInterfaceNumberByMAC func(mac string) (int, error)
	OnGetMACByInterfaceNumber func(ifaceNum int) (string, error)
}

func (s *MigrateSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

// n is the number of devices, routes, and rules that will be created in
// setUpRoutingTable() as fixtures for this test suite.
const n = 5

func (m *MigrateSuite) TestMigrateENIDatapathUpgradeSuccess(c *C) {
	// First, we need to setup the Linux routing policy database to mimic a
	// broken setup (1). Then we will call MigrateENIDatapath (2).

	// This test case will cover the successful path. We will create:
	//   - One rule with the old priority referencing the old table ID.
	//   - One route with the old table ID.
	// After we call MigrateENIDatapath(), we assert that:
	//   - The rule has switched to the new priority and references the new
	//     table ID.
	//   - The route has the new table ID.

	runFuncInNetNS(c, func() {
		// (1) Setting up the routing table.

		// Pick an arbitrary iface index. In the old table ID scheme, we used this
		// index as the table ID. All the old rules and routes will be set up with
		// this table ID.
		index := 5
		tableID := 11

		// (1) Setting up the routing table for testing upgrade.
		//
		// The reason we pass index twice is because we want to use the ifindex as
		// the table ID.
		devIfNumLookup, _ := setUpRoutingTable(c, index, index, linux_defaults.RulePriorityEgress)

		// Set up the rpdb mocks to just forward to netlink implementation.
		m.defaultNetlinkMock()

		// Set up the interfaceDB mock. We don't actually need to search by MAC
		// address in this test because we only have just one device. The actual
		// implementation will search the CiliumNode resource for the ENI device
		// matching.
		m.OnGetInterfaceNumberByMAC = func(mac string) (int, error) {
			// In setUpRoutingTable(), we used an arbitrary scheme that maps
			// each device created with an interface number of loop count (i)
			// plus one.
			return devIfNumLookup[mac], nil
		}

		// (2) Make the call to modifying the routing table.
		mig := migrator{rpdb: m, getter: m}
		migrated, failed := mig.MigrateENIDatapath(false)
		c.Assert(migrated, Equals, n)
		c.Assert(failed, Equals, 0)

		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: index,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 0) // We don't expect any routes with the old table ID.

		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: tableID,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 1) // We only expect one route that we created above in the setup.
		c.Assert(routes[0].Table, Not(Equals), index)

		rules, err := findRulesByPriority(linux_defaults.RulePriorityEgress)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 0) // We don't expect any rules from old priority.

		rules, err = findRulesByPriority(linux_defaults.RulePriorityEgressv2)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 5) // We expect all rules to be migrated to new priority.
		c.Assert(rules[0].Table, Not(Equals), index)
	})
}

func (m *MigrateSuite) TestMigrateENIDatapathUpgradeFailure(c *C) {
	// This test case will cover one failure path where we successfully migrate
	// all the old rules and routes, but fail to cleanup the old rule. This
	// test case will be set up identically to the successful case. After we
	// call MigrateENIDatapath(), we assert that we failed to migrate 1 rule.
	// We assert that the revert of the upgrade was successfully as well,
	// meaning we expect the old rules and routes to be reinstated.

	runFuncInNetNS(c, func() {
		index := 5
		devIfNumLookup, _ := setUpRoutingTable(c, index, index, linux_defaults.RulePriorityEgress)

		m.defaultNetlinkMock()

		// Here we inject the error on deleting a rule. The first call we want to
		// fail, but the second we want to succeed, because that will be the
		// revert.
		var onRuleDelCount int
		m.OnRuleDel = func(r *netlink.Rule) error {
			if onRuleDelCount == 0 {
				onRuleDelCount++
				return errors.New("fake error")
			}
			return netlink.RuleDel(r)
		}

		// Set up the interfaceDB mock. We don't actually need to search by MAC
		// address in this test because we only have just one device. The actual
		// implementation will search the CiliumNode resource for the ENI device
		// matching.
		m.OnGetInterfaceNumberByMAC = func(mac string) (int, error) {
			// In setUpRoutingTable(), we used an arbitrary scheme that maps
			// each device created with an interface number of loop count (i)
			// plus one.
			return devIfNumLookup[mac], nil
		}

		mig := migrator{rpdb: m, getter: m}
		migrated, failed := mig.MigrateENIDatapath(false)
		c.Assert(migrated, Equals, 4)
		c.Assert(failed, Equals, 1)

		tableID := 11
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: index,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 1) // We expect old route to be untouched b/c we failed.
		c.Assert(routes[0].Table, Equals, index)

		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: tableID,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 0) // We don't expect any routes under new table ID b/c of revert.

		rules, err := findRulesByPriority(linux_defaults.RulePriorityEgress)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 1) // We expect the old rule to be reinstated.
		c.Assert(rules[0].Table, Equals, index)

		rules, err = findRulesByPriority(linux_defaults.RulePriorityEgressv2)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 4) // We expect the rest of the rules to be upgraded.
	})
}

func (m *MigrateSuite) TestMigrateENIDatapathDowngradeSuccess(c *C) {
	// This test case will cover the successful downgrade path. We will create:
	//   - One rule with the new priority referencing the new table ID.
	//   - One route with the new table ID.
	// After we call MigrateENIDatapath(), we assert that:
	//   - The rule has switched to the old priority and references the old
	//     table ID.
	//   - The route has the old table ID.

	runFuncInNetNS(c, func() {
		// (1) Setting up the routing table.

		// Pick an arbitrary table ID. In the new table ID scheme, it is the
		// interface number + an offset of 10
		// (linux_defaults.RouteTableInterfacesOffset).
		//
		// Pick an ifindex and table ID.
		index := 5
		tableID := 11

		// (1) Setting up the routing table for testing downgrade, hence creating
		// rules with RulePriorityEgressv2.
		_, devMACLookup := setUpRoutingTable(c, index, tableID, linux_defaults.RulePriorityEgressv2)

		// Set up the rpdb mocks to just forward to netlink implementation.
		m.defaultNetlinkMock()

		// Set up the interfaceDB mock. The MAC address returned is coming from the
		// dummy ENI device we set up in setUpRoutingTable(). The actual
		// implementation will search the CiliumNode resource for the ENI device
		// matching.
		m.OnGetMACByInterfaceNumber = func(i int) (string, error) {
			// In setUpRoutingTable(), we used an arbitrary scheme for the
			// device name. It is simply the loop counter.
			return devMACLookup[fmt.Sprintf("gotestdummy%d", i)], nil
		}

		// (2) Make the call to modifying the routing table.
		mig := migrator{rpdb: m, getter: m}
		migrated, failed := mig.MigrateENIDatapath(true)
		c.Assert(migrated, Equals, n)
		c.Assert(failed, Equals, 0)

		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: tableID,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 0) // We don't expect any routes with the new table ID.

		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: index,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 1) // We only expect one route with the old table ID.
		c.Assert(routes[0].Table, Not(Equals), tableID)

		rules, err := findRulesByPriority(linux_defaults.RulePriorityEgressv2)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 0) // We don't expect any rules with this priority.

		rules, err = findRulesByPriority(linux_defaults.RulePriorityEgress)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 5) // We expect all rules to have the original priority.
		c.Assert(rules[0].Table, Not(Equals), tableID)
	})
}

func (m *MigrateSuite) TestMigrateENIDatapathDowngradeFailure(c *C) {
	// This test case will cover one downgrade failure path where we failed to
	// migrate the rule to the old scheme. This test case will be set up
	// identically to the successful case. "New" meaning the rules and routes
	// using the new datapath scheme, hence downgrading. After we call
	// MigrateENIDatapath(), we assert that we failed to migrate 1 rule. We
	// assert that the revert of the downgrade was successfully as well,
	// meaning we expect the "newer" rules and routes to be reinstated.

	runFuncInNetNS(c, func() {
		index := 5
		tableID := 11
		_, devMACLookup := setUpRoutingTable(c, index, tableID, linux_defaults.RulePriorityEgressv2)

		m.defaultNetlinkMock()

		// Here we inject the error on adding a rule. The first call we want to
		// fail, but the second we want to succeed, because that will be the
		// revert.
		var onRuleAddCount int
		m.OnRuleAdd = func(r *netlink.Rule) error {
			if onRuleAddCount == 0 {
				onRuleAddCount++
				return errors.New("fake error")
			}
			return netlink.RuleAdd(r)
		}

		// Set up the interfaceDB mock. The MAC address returned is coming from the
		// dummy ENI device we set up in setUpRoutingTable().
		m.OnGetMACByInterfaceNumber = func(i int) (string, error) {
			// In setUpRoutingTable(), we used an arbitrary scheme for the
			// device name. It is simply the loop counter.
			return devMACLookup[fmt.Sprintf("gotestdummy%d", i)], nil
		}

		mig := migrator{rpdb: m, getter: m}
		migrated, failed := mig.MigrateENIDatapath(true)
		c.Assert(migrated, Equals, n-1) // One failed migration.
		c.Assert(failed, Equals, 1)

		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: tableID,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 1) // We expect "new" route to be untouched b/c we failed to delete.
		c.Assert(routes[0].Table, Equals, tableID)

		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: index,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 0) // We don't expect routes under original table ID b/c of revert.

		rules, err := findRulesByPriority(linux_defaults.RulePriorityEgressv2)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 1) // We expect the "new" rule to be reinstated.
		c.Assert(rules[0].Table, Equals, tableID)

		rules, err = findRulesByPriority(linux_defaults.RulePriorityEgress)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, n-1) // Successfully migrated rules.
	})
}

func (m *MigrateSuite) TestMigrateENIDatapathPartial(c *C) {
	// This test case will cover one case where we find a partial rule. It will
	// be set up with a rule with the newer priority and the user has indicated
	// compatbility=false, meaning they intend to upgrade. The fact that
	// there's already a rule with a newer priority indicates that a previous
	// migration has taken place and potentially failed. This simulates Cilium
	// starting up from a potentially failed previous migration.
	// After we call MigrateENIDatapath(), we assert that:
	//   - We still upgrade the remaining rules that need to be migrated.
	//   - We ignore the partially migrated rule.

	runFuncInNetNS(c, func() {
		index := 5
		// ifaceNumber := 1
		newTableID := 11

		devIfNumLookup, _ := setUpRoutingTable(c, index, index, linux_defaults.RulePriorityEgress)

		// Insert fake rule that has the newer priority to simulate it as
		// "partially migrated".
		err := exec.Command("ip", "rule", "add",
			"from", "10.1.0.0/24",
			"to", "all",
			"table", fmt.Sprintf("%d", newTableID),
			"priority", fmt.Sprintf("%d", linux_defaults.RulePriorityEgressv2)).Run()
		c.Assert(err, IsNil)

		m.defaultNetlinkMock()

		m.OnGetInterfaceNumberByMAC = func(mac string) (int, error) {
			return devIfNumLookup[mac], nil
		}

		mig := migrator{rpdb: m, getter: m}
		migrated, failed := mig.MigrateENIDatapath(false)
		c.Assert(migrated, Equals, n)
		c.Assert(failed, Equals, 0)

		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: newTableID,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 1) // We expect one migrated route.
		c.Assert(routes[0].Table, Equals, newTableID)

		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: index,
		}, netlink.RT_FILTER_TABLE)
		c.Assert(err, IsNil)
		c.Assert(routes, HasLen, 0) // We don't expect any routes under old table ID.

		rules, err := findRulesByPriority(linux_defaults.RulePriorityEgressv2)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, n+1) // We expect all migrated rules and the partially migrated rule.
		c.Assert(rules[0].Table, Equals, newTableID)
		c.Assert(rules[1].Table, Equals, newTableID)

		rules, err = findRulesByPriority(linux_defaults.RulePriorityEgress)
		c.Assert(err, IsNil)
		c.Assert(rules, HasLen, 0) // We don't expect any rules with the old priority.
	})
}

// setUpRoutingTable initializes the routing table for this test suite. The
// starting ifindex, tableID, and the priority are passed in to give contron to
// the caller on the setup. The two return values are:
//  1. Map of string to int, representing a mapping from MAC addrs to
//     interface numbers.
//  2. Map of string to string, representing a mapping from device name to MAC
//     addrs.
//
// (1) is used for the upgrade test cases where the GetInterfaceNumberByMAC
// mock is used. (2) is used for the downgrade test cases where the
// GetMACByInterfaceNumber mock is used. These maps are used in their
// respectives mocks to return the desired result data depending on the test.
func setUpRoutingTable(c *C, ifindex, tableID, priority int) (map[string]int, map[string]string) {
	devIfNum := make(map[string]int)
	devMAC := make(map[string]string)

	// Create n sets of a dummy interface, a route, and a rule.
	//
	// Each dummy interface has a /24 from the private range of 172.16.0.0/20.
	//
	// Each route will be a default route to the gateway IP of the interface's
	// subnet.
	//
	// Each rule will be from the interface's subnet to all.
	for i := 1; i <= n; i++ {
		devName := fmt.Sprintf("gotestdummy%d", i)

		gw := net.ParseIP(fmt.Sprintf("172.16.%d.1", i))
		_, linkCIDR, err := net.ParseCIDR(fmt.Sprintf("172.16.%d.2/24", i))
		c.Assert(err, IsNil)

		linkIndex := ifindex + (i - 1)
		newTableID := tableID + (i - 1)

		dummyTmpl := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:  devName,
				Index: linkIndex,
			},
		}
		c.Assert(netlink.LinkAdd(dummyTmpl), IsNil)
		c.Assert(netlink.LinkSetUp(dummyTmpl), IsNil)
		c.Assert(netlink.AddrAdd(dummyTmpl, &netlink.Addr{
			IPNet: linkCIDR,
		}), IsNil)
		c.Assert(netlink.RouteAdd(&netlink.Route{
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Gw:        gw,
			LinkIndex: dummyTmpl.Index,
			Table:     newTableID,
		}), IsNil)

		// _, cidr, err := net.ParseCIDR("172.16.0.2/24")
		// c.Assert(err, IsNil)
		// c.Assert(netlink.RuleAdd(&netlink.Rule{
		// 	// Src:      &net.IPNet{IP: net.ParseIP("172.16.0.2"), Mask: net.CIDRMask(24, 32)},
		// 	Src: cidr,
		// 	// Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		// 	Priority: linux_defaults.RulePriorityEgress,
		// 	Table:    dummyTmpl.Index,
		// }), IsNil)

		// TODO(christarazi): Must shell out here due to netlink request (above)
		// resulting in EINVAL. See https://github.com/cilium/cilium/issues/14383.
		err = exec.Command("ip", "rule", "add",
			"from", linkCIDR.String(),
			"to", "all",
			"table", fmt.Sprintf("%d", newTableID),
			"priority", fmt.Sprintf("%d", priority)).Run()
		c.Assert(err, IsNil)

		// Return the MAC address of the dummy device, which acts as the ENI.
		link, err := netlink.LinkByName(devName)
		c.Assert(err, IsNil)

		mac := link.Attrs().HardwareAddr.String()

		// Arbitrarily use an offset of 1 as the interface number. It doesn't
		// matter as long as we're consistent.
		devIfNum[mac] = i
		devMAC[devName] = mac
	}

	return devIfNum, devMAC
}

func findRulesByPriority(prio int) ([]netlink.Rule, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	return filterRulesByPriority(rules, prio), nil
}

func (m *MigrateSuite) defaultNetlinkMock() {
	m.OnRuleList = func(family int) ([]netlink.Rule, error) { return netlink.RuleList(family) }
	m.OnRuleAdd = func(rule *netlink.Rule) error { return netlink.RuleAdd(rule) }
	m.OnRuleDel = func(rule *netlink.Rule) error { return netlink.RuleDel(rule) }
	m.OnRouteListFiltered = func(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
		return netlink.RouteListFiltered(family, filter, mask)
	}
	m.OnRouteAdd = func(route *netlink.Route) error { return netlink.RouteAdd(route) }
	m.OnRouteDel = func(route *netlink.Route) error { return netlink.RouteDel(route) }
	m.OnRouteReplace = func(route *netlink.Route) error { return netlink.RouteReplace(route) }
	m.OnLinkList = func() ([]netlink.Link, error) { return netlink.LinkList() }
	m.OnLinkByIndex = func(ifindex int) (netlink.Link, error) { return netlink.LinkByIndex(ifindex) }
}

func (m *MigrateSuite) RuleList(family int) ([]netlink.Rule, error) {
	if m.OnRuleList != nil {
		return m.OnRuleList(family)
	}
	panic("OnRuleList should not have been called")
}

func (m *MigrateSuite) RuleAdd(rule *netlink.Rule) error {
	if m.OnRuleAdd != nil {
		return m.OnRuleAdd(rule)
	}
	panic("OnRuleAdd should not have been called")
}

func (m *MigrateSuite) RuleDel(rule *netlink.Rule) error {
	if m.OnRuleDel != nil {
		return m.OnRuleDel(rule)
	}
	panic("OnRuleDel should not have been called")
}

func (m *MigrateSuite) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	if m.OnRouteListFiltered != nil {
		return m.OnRouteListFiltered(family, filter, mask)
	}
	panic("OnRouteListFiltered should not have been called")
}

func (m *MigrateSuite) RouteAdd(route *netlink.Route) error {
	if m.OnRouteAdd != nil {
		return m.OnRouteAdd(route)
	}
	panic("OnRouteAdd should not have been called")
}

func (m *MigrateSuite) RouteDel(route *netlink.Route) error {
	if m.OnRouteDel != nil {
		return m.OnRouteDel(route)
	}
	panic("OnRouteDel should not have been called")
}

func (m *MigrateSuite) RouteReplace(route *netlink.Route) error {
	if m.OnRouteReplace != nil {
		return m.OnRouteReplace(route)
	}
	panic("OnRouteReplace should not have been called")
}

func (m *MigrateSuite) LinkList() ([]netlink.Link, error) {
	if m.OnLinkList != nil {
		return m.OnLinkList()
	}
	panic("OnLinkList should not have been called")
}

func (m *MigrateSuite) LinkByIndex(ifindex int) (netlink.Link, error) {
	if m.OnLinkByIndex != nil {
		return m.OnLinkByIndex(ifindex)
	}
	panic("OnLinkByIndex should not have been called")
}

func (m *MigrateSuite) GetInterfaceNumberByMAC(mac string) (int, error) {
	if m.OnGetInterfaceNumberByMAC != nil {
		return m.OnGetInterfaceNumberByMAC(mac)
	}
	panic("OnGetInterfaceNumberByMAC should not have been called")
}

func (m *MigrateSuite) GetMACByInterfaceNumber(ifaceNum int) (string, error) {
	if m.OnGetMACByInterfaceNumber != nil {
		return m.OnGetMACByInterfaceNumber(ifaceNum)
	}
	panic("OnGetMACByInterfaceNumber should not have been called")
}
