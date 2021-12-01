// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package egressgateway

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	testInterface = "cilium_test"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"

	destCIDR = "1.1.1.0/24"

	egressIP1   = "192.168.101.1"
	egressCIDR1 = "192.168.101.1/24"

	egressIP2   = "192.168.102.1"
	egressCIDR2 = "192.168.102.1/24"

	zeroIP4 = "0.0.0.0"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}
)

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

type k8sCacheSyncedCheckerMock struct {
	synced bool
}

func (k *k8sCacheSyncedCheckerMock) WaitUntilK8sCacheIsSynced() {
	for {
		if k.synced {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func (k *k8sCacheSyncedCheckerMock) K8sCacheIsSynced() bool {
	return k.synced
}

// Hook up gocheck into the "go test" runner.
type EgressGatewayTestSuite struct{}

var _ = Suite(&EgressGatewayTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressGatewayTestSuite) SetUpSuite(c *C) {
	bpf.CheckOrMountFS("")
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)

	option.Config.EnableEgressGateway = true

	egressmap.InitEgressMaps()
}

func (k *EgressGatewayTestSuite) TestEgressGatewayManager(c *C) {
	defer cleanupPolicies()

	k8sCacheSyncedChecker := &k8sCacheSyncedCheckerMock{}

	egressGatewayManager := NewEgressGatewayManager(k8sCacheSyncedChecker)
	c.Assert(egressGatewayManager, NotNil)

	k8sCacheSyncedChecker.synced = true

	// Create a new policy
	policy1 := newEgressPolicyConfig("policy-1", ep1Labels, destCIDR, egressIP1)
	egressGatewayManager.OnAddEgressPolicy(policy1)

	assertEgressRules(c, []egressRule{})

	// Add a new endpoint which matches policy-1
	ep1 := newEndpoint("ep-1", ep1IP, ep1Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, []egressRule{
		{ep1IP, destCIDR, egressIP1, egressIP1},
	})

	// Update the endpoint labels in order for it to not be a match
	oldEp1Labels := ep1.Identity.Labels
	ep1.Identity.Labels = []string{}
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, []egressRule{})

	// Restore the old endpoint lables in order for it to be a match
	ep1.Identity.Labels = oldEp1Labels
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, []egressRule{
		{ep1IP, destCIDR, egressIP1, egressIP1},
	})

	// Create a new policy
	policy2 := newEgressPolicyConfig("policy-2", ep2Labels, destCIDR, egressIP2)
	egressGatewayManager.OnAddEgressPolicy(policy2)

	assertEgressRules(c, []egressRule{
		{ep1IP, destCIDR, egressIP1, egressIP1},
	})

	// Add a new endpoint which matches policy-2
	ep2 := newEndpoint("ep-2", ep2IP, ep2Labels)
	egressGatewayManager.OnUpdateEndpoint(&ep2)

	assertEgressRules(c, []egressRule{
		{ep1IP, destCIDR, egressIP1, egressIP1},
		{ep2IP, destCIDR, egressIP2, egressIP2},
	})

	// Update the endpoint labels for policy-1 in order for it to not be a match
	oldEp1Labels = ep1.Identity.Labels
	ep1.Identity.Labels = []string{}
	egressGatewayManager.OnUpdateEndpoint(&ep1)

	assertEgressRules(c, []egressRule{
		{ep2IP, destCIDR, egressIP2, egressIP2},
	})
}

func cleanupPolicies() {
	for _, ep := range []string{ep1IP, ep2IP} {
		deleteEgressRule(ep, destCIDR)
	}
}

func newEgressPolicyConfig(policyName string, labels map[string]string, destinationCIDR, egressIP string) PolicyConfig {
	_, destCIDR, _ := net.ParseCIDR(destinationCIDR)
	eip := net.ParseIP(egressIP)

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
		dstCIDRs: []*net.IPNet{destCIDR},
		egressIP: eip,
	}
}

func newEndpoint(name, ip string, labels map[string]string) k8sTypes.CiliumEndpoint {
	epLabels := []string{}
	for k, v := range labels {
		epLabels = append(epLabels, fmt.Sprintf("k8s:%s=%s", k, v))
	}

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
		},
		Identity: &v2.EndpointIdentity{
			Labels: epLabels,
		},
		Networking: &v2.EndpointNetworking{
			Addressing: v2.AddressPairList{
				&v2.AddressPair{
					IPV4: ip,
				},
			},
		},
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

func assertEgressRules(c *C, rules []egressRule) {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := egressmap.EgressPolicyMap.Lookup(r.sourceIP, r.destCIDR)
		c.Assert(err, IsNil)

		c.Assert(policyVal.GetEgressIP().Equal(r.egressIP), Equals, true)
		c.Assert(policyVal.GetGatewayIP().Equal(r.gatewayIP), Equals, true)
	}

	egressmap.EgressPolicyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, &r.destCIDR) && val.Match(r.egressIP, r.gatewayIP) {
					return
				}
			}

			c.Fatal("Untracked egress policy")
		})
}

func deleteEgressRule(sourceIP, destCIDR string) {
	pr := parseEgressRule(sourceIP, destCIDR, zeroIP4, zeroIP4)
	egressmap.EgressPolicyMap.Delete(pr.sourceIP, pr.destCIDR)
}
