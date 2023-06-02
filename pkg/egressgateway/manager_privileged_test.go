// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"net"
	"testing"

	. "github.com/cilium/checkmate"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testInterface1 = "cilium_egw1"

	node1 = "k8s1"
	node2 = "k8s2"

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"

	destCIDR      = "1.1.1.0/24"
	excludedCIDR1 = "1.1.1.22/32"
	excludedCIDR2 = "1.1.1.240/30"

	egressIP1   = "192.168.101.1"
	egressCIDR1 = "192.168.101.1/24"

	zeroIP4 = "0.0.0.0"

	// Special values for gatewayIP, see pkg/egressgateway/manager.go
	gatewayNotFoundValue     = "0.0.0.0"
	gatewayExcludedCIDRValue = "0.0.0.1"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	nodeGroupNotFoundLabels = map[string]string{"label1": "notfound"}
	nodeGroup1Labels        = map[string]string{"label1": "1"}
	nodeGroup2Labels        = map[string]string{"label2": "2"}

	nodeGroupNotFoundSelector = &slimv1.LabelSelector{MatchLabels: nodeGroupNotFoundLabels}
	nodeGroup1Selector        = &slimv1.LabelSelector{MatchLabels: nodeGroup1Labels}
	nodeGroup2Selector        = &slimv1.LabelSelector{MatchLabels: nodeGroup2Labels}
)

type ipRule struct {
	sourceIP   string
	destCIDR   string
	egressIP   string
	ifaceIndex int
}

type parsedIPRule struct {
	sourceIP   net.IP
	destCIDR   net.IPNet
	egressIP   net.IPNet
	ifaceIndex int
}

type egressRule struct {
	sourceIP  string
	destCIDR  string
	egressIP  string
	gatewayIP string
}

type parsedEgressRule struct {
	sourceIP  net.IP
	destCIDR  net.IPNet
	egressIP  net.IP
	gatewayIP net.IP
}

// Hook up gocheck into the "go test" runner.
type EgressGatewayTestSuite struct {
	hive        *hive.Hive
	manager     *Manager
	cacheStatus k8s.CacheStatus
}

var _ = Suite(&EgressGatewayTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressGatewayTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)

	nodeTypes.SetName(node1)
}

func (k *EgressGatewayTestSuite) SetUpTest(c *C) {
	k.cacheStatus = make(k8s.CacheStatus)
	k.hive = hive.New(
		egressmap.Cell,
		cell.Provide(NewEgressGatewayManager),
		cell.Provide(
			func() Config { return Config{true} },
			func() *option.DaemonConfig { return &option.DaemonConfig{EnableIPv4EgressGateway: true} },
			func() k8s.CacheStatus { return k.cacheStatus },
			func() cache.IdentityAllocator { return identityAllocator },
		),
		cell.Invoke(func(m *Manager) {
			k.manager = m
		}),
	)
	c.Assert(k.hive.Start(context.Background()), IsNil)
	c.Assert(k.manager, NotNil)
}

func (k *EgressGatewayTestSuite) TearDownTest(c *C) {
	c.Assert(k.hive.Stop(context.Background()), IsNil)
}

func (k *EgressGatewayTestSuite) TestEgressGatewayManager(c *C) {
	testInterface1Idx := createTestInterface(testInterface1, egressCIDR1)

	defer destroyTestInterface(testInterface1)

	policyMap := k.manager.policyMap
	defer cleanupPolicies(policyMap)

	egressGatewayManager := k.manager
	assertIPRules(c, []ipRule{})

	close(k.cacheStatus)

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	egressGatewayManager.OnUpdateNode(node1)

	node2 := newCiliumNode(node2, node2IP, nodeGroup2Labels)
	egressGatewayManager.OnUpdateNode(node2)

	// Create a new policy
	policy1 := newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{}, nodeGroup1Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{})
	assertIPRules(c, []ipRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Update the endpoint labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, policyMap, []egressRule{})
	assertIPRules(c, []ipRule{})

	// Restore the old endpoint lables in order for it to be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Create a new policy
	policy2 := newEgressPolicyConfigWithNodeSelector("policy-2", ep2Labels, destCIDR, []string{}, nodeGroup2Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy2)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Add a new endpoint and ID which matches policy-2
	ep2, _ := newEndpointAndIdentity("ep-2", ep2IP, ep2Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep2)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Test if disabling the --install-egress-gateway-routes agent option
	// will result in stale IP routes/rules getting removed
	egressGatewayManager.installRoutes = false
	egressGatewayManager.reconcile(eventNone)

	assertIPRules(c, []ipRule{})

	// Enabling it back should result in the routes/rules being in place
	// again
	egressGatewayManager.installRoutes = true
	egressGatewayManager.reconcile(eventNone)

	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Test excluded CIDRs by adding one to policy-1
	policy1 = newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{excludedCIDR1}, nodeGroup1Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// When an excluded CIDRs is specified, the manager will install
	// multiple IP rules, one for each of the CIDRs we obtain by subtracting
	// the excluded CIDR (1.1.1.1/22) from the destination CIDR (1.1.1.0/24):
	//
	// $ netcalc sub 1.1.1.0/24 1.1.1.22/32
	// 1.1.1.0/28
	// 1.1.1.16/30
	// 1.1.1.20/31
	// 1.1.1.23/32
	// 1.1.1.24/29
	// 1.1.1.32/27
	// 1.1.1.64/26
	// 1.1.1.128/25
	assertIPRules(c, []ipRule{
		{ep1IP, "1.1.1.128/25", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.64/26", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.32/27", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.0/28", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.24/29", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.16/30", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.20/31", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.23/32", egressCIDR1, testInterface1Idx},
	})

	// Add a second excluded CIDR to policy-1
	policy1 = newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{excludedCIDR1, excludedCIDR2}, nodeGroup1Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// $ for net in $(netcalc sub 1.1.1.0/24 1.1.1.22/32); do
	//    netcalc sub $net 1.1.1.240/30
	// done
	// 1.1.1.0/28
	// 1.1.1.16/30
	// 1.1.1.20/31
	// 1.1.1.23/32
	// 1.1.1.24/29
	// 1.1.1.32/27
	// 1.1.1.64/26
	// 1.1.1.128/26
	// 1.1.1.192/27
	// 1.1.1.224/28
	// 1.1.1.244/30
	// 1.1.1.248/29
	assertIPRules(c, []ipRule{
		{ep1IP, "1.1.1.0/28", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.16/30", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.20/31", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.23/32", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.24/29", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.32/27", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.64/26", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.128/26", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.192/27", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.224/28", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.244/30", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.248/29", egressCIDR1, testInterface1Idx},
	})

	// Remove the first excluded CIDR from policy-1
	policy1 = newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{excludedCIDR2}, nodeGroup1Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// $ netcalc sub 1.1.1.0/24 1.1.1.240/30
	// 1.1.1.0/25
	// 1.1.1.128/26
	// 1.1.1.192/27
	// 1.1.1.224/28
	// 1.1.1.244/30
	// 1.1.1.248/29
	assertIPRules(c, []ipRule{
		{ep1IP, "1.1.1.0/25", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.128/26", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.192/27", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.224/28", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.244/30", egressCIDR1, testInterface1Idx},
		{ep1IP, "1.1.1.248/29", egressCIDR1, testInterface1Idx},
	})

	// Remove the second excluded CIDR
	policy1 = newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{}, nodeGroup1Selector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	assertIPRules(c, []ipRule{
		{ep1IP, destCIDR, egressCIDR1, testInterface1Idx},
	})

	// Test matching no gateway
	policy1 = newEgressPolicyConfigWithNodeSelector("policy-1", ep1Labels, destCIDR, []string{}, nodeGroupNotFoundSelector, testInterface1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep1IP, destCIDR, zeroIP4, gatewayNotFoundValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	assertIPRules(c, []ipRule{})

	// Update the endpoint labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, policyMap, []egressRule{
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertIPRules(c, []ipRule{})
}

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate()
	if err != nil {
		t.Fatal(err)
	}
}

func createTestInterface(iface string, addr string) int {
	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		panic(err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		panic(err)
	}

	a, _ := netlink.ParseAddr(addr)
	netlink.AddrAdd(link, a)

	return link.Attrs().Index
}

func destroyTestInterface(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkDel(link); err != nil {
		return err
	}

	return nil
}

func cleanupPolicies(policyMap egressmap.PolicyMap) {
	for _, ep := range []string{ep1IP, ep2IP} {
		pr := parseEgressRule(ep, destCIDR, zeroIP4, zeroIP4)
		policyMap.Delete(pr.sourceIP, pr.destCIDR)
	}
}

func newCiliumNode(name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	return nodeTypes.Node{
		Name:   name,
		Labels: nodeLabels,
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(nodeIP),
			},
		},
	}
}

func newEgressPolicyConfigWithNodeSelector(policyName string, labels map[string]string, destinationCIDR string, excludedCIDRs []string, selector *v1.LabelSelector, iface string) PolicyConfig {
	_, parsedDestinationCIDR, _ := net.ParseCIDR(destinationCIDR)

	parsedExcludedCIDRs := []*net.IPNet{}
	for _, excludedCIDR := range excludedCIDRs {
		_, parsedExcludedCIDR, _ := net.ParseCIDR(excludedCIDR)
		parsedExcludedCIDRs = append(parsedExcludedCIDRs, parsedExcludedCIDR)
	}

	return PolicyConfig{
		id: types.NamespacedName{
			Name: policyName,
		},
		endpointSelectors: []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: labels,
				},
			},
		},
		dstCIDRs:      []*net.IPNet{parsedDestinationCIDR},
		excludedCIDRs: parsedExcludedCIDRs,
		policyGwConfig: &policyGatewayConfig{
			nodeSelector: api.NewESFromK8sLabelSelector("", selector),
			iface:        iface,
		},
	}
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentity(name, ip string, epLabels map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(epLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
		},
		Identity: &v2.EndpointIdentity{
			ID: int64(id.ID),
		},
		Networking: &v2.EndpointNetworking{
			Addressing: v2.AddressPairList{
				&v2.AddressPair{
					IPV4: ip,
				},
			},
		},
	}, id
}

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	ctx := context.Background()

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, labels.Map2Labels(newEpLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	return newID
}

func parseIPRule(sourceIP, destCIDR, egressIP string, ifaceIndex int) parsedIPRule {
	sip := net.ParseIP(sourceIP)
	if sip == nil {
		panic("Invalid source IP")
	}

	_, dc, err := net.ParseCIDR(destCIDR)
	if err != nil {
		panic("Invalid destination CIDR")
	}

	eip, ecidr, _ := net.ParseCIDR(egressIP)
	if eip == nil {
		panic("Invalid egress IP")
	}

	return parsedIPRule{
		sourceIP:   sip,
		destCIDR:   *dc,
		egressIP:   net.IPNet{IP: eip, Mask: ecidr.Mask},
		ifaceIndex: ifaceIndex,
	}
}

func assertIPRules(c *C, rules []ipRule) {
	parsedRules := []parsedIPRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseIPRule(r.sourceIP, r.destCIDR, r.egressIP, r.ifaceIndex))
	}

	installedRules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{Priority: linux_defaults.RulePriorityEgressGateway})
	if err != nil {
		panic("Cannot list IP rules")
	}

nextRule:
	for _, rule := range parsedRules {
		for _, installedRule := range installedRules {
			if rule.sourceIP.Equal(installedRule.Src.IP) && rule.destCIDR.String() == installedRule.Dst.String() &&
				rule.ifaceIndex == installedRule.Table-linux_defaults.RouteTableEgressGatewayInterfacesOffset {

				assertIPRoutes(c, rule.egressIP, rule.ifaceIndex)
				continue nextRule
			}
		}

		c.Fatal("Missing IP rule")
	}

nextInstalledRule:
	for _, installedRule := range installedRules {
		for _, rule := range parsedRules {
			if rule.sourceIP.Equal(installedRule.Src.IP) && rule.destCIDR.String() == installedRule.Dst.String() &&
				rule.ifaceIndex == installedRule.Table-linux_defaults.RouteTableEgressGatewayInterfacesOffset {
				continue nextInstalledRule
			}
		}

		c.Fatal("Untracked IP rule")
	}
}

func assertIPRoutes(c *C, egressIP net.IPNet, ifaceIndex int) {
	eniGatewayIP := getFirstIPInHostRange(egressIP)
	routingTableIdx := egressGatewayRoutingTableIdx(ifaceIndex)

	route, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		LinkIndex: ifaceIndex,
		Dst:       &net.IPNet{IP: eniGatewayIP, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     routingTableIdx,
	}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST|netlink.RT_FILTER_SCOPE|netlink.RT_FILTER_TABLE)

	if err != nil || route == nil {
		c.Fatal("Cannot find nexthop route to the VPC subnet:", err)
	}

	route, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Table: routingTableIdx,
		Gw:    eniGatewayIP,
	}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_GW)

	if err != nil || route == nil {
		c.Fatal("Cannot find default route to the VPC:", err)
	}
}

func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string) parsedEgressRule {
	sip := net.ParseIP(sourceIP)
	if sip == nil {
		panic("Invalid source IP")
	}

	_, dc, err := net.ParseCIDR(destCIDR)
	if err != nil {
		panic("Invalid destination CIDR")
	}

	eip := net.ParseIP(egressIP)
	if eip == nil {
		panic("Invalid egress IP")
	}

	gip := net.ParseIP(gatewayIP)
	if gip == nil {
		panic("Invalid gateway IP")
	}

	return parsedEgressRule{
		sourceIP:  sip,
		destCIDR:  *dc,
		egressIP:  eip,
		gatewayIP: gip,
	}
}

func assertEgressRules(c *C, policyMap egressmap.PolicyMap, rules []egressRule) {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		c.Assert(err, IsNil)

		c.Assert(policyVal.GetEgressIP().Equal(r.egressIP), Equals, true)
		c.Assert(policyVal.GetGatewayIP().Equal(r.gatewayIP), Equals, true)
	}

	policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, &r.destCIDR) && val.Match(r.egressIP, r.gatewayIP) {
					return
				}
			}

			c.Fatal("Untracked egress policy")
		})
}
