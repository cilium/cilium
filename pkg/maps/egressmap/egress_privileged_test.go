// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package egressmap

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type EgressMapTestSuite struct{}

var _ = Suite(&EgressMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressMapTestSuite) SetUpSuite(c *C) {
	bpf.CheckOrMountFS("")
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
}

func (k *EgressMapTestSuite) TestEgressMap(c *C) {
	err := initEgressPolicyMap("test_egress_policy_v4", true)
	c.Assert(err, IsNil)
	defer EgressPolicyMap.Unpin()

	err = initEgressCtMap("test_egress_ct_v4", true)
	c.Assert(err, IsNil)
	defer EgressCtMap.Unpin()

	sourceIP1 := net.ParseIP("1.1.1.1")
	sourceIP2 := net.ParseIP("1.1.1.2")

	_, destCIDR1, err := net.ParseCIDR("2.2.1.0/24")
	c.Assert(err, IsNil)
	_, destCIDR2, err := net.ParseCIDR("2.2.2.0/24")
	c.Assert(err, IsNil)

	egressIP1 := net.ParseIP("3.3.3.1")
	egressIP2 := net.ParseIP("3.3.3.2")

	gatewayIP1 := net.ParseIP("4.4.4.1")
	gatewayIP2 := net.ParseIP("4.4.4.2")

	// This will create 2 policies, respectively with 2 and 1 egress GWs:
	//
	// Source IP   Destination CIDR   Egress IP   Gateway
	// 1.1.1.1     2.2.1.0/24         3.3.3.1     0 => 4.4.4.1
	//                                            1 => 4.4.4.2
	// 1.1.1.2     2.2.2.0/24         3.3.3.2     0 => 4.4.4.1

	err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP1, gatewayIP1)
	c.Assert(err, IsNil)

	err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP1, gatewayIP2)
	c.Assert(err, IsNil)

	err = InsertEgressGateway(sourceIP2, *destCIDR2, egressIP2, gatewayIP1)
	c.Assert(err, IsNil)

	val, err := EgressPolicyMap.Lookup(sourceIP1, *destCIDR1)
	c.Assert(err, IsNil)

	c.Assert(val.Size, Equals, uint32(2))
	c.Assert(val.EgressIP.IP().Equal(egressIP1), Equals, true)
	c.Assert(val.GatewayIPs[0].IP().Equal(gatewayIP1), Equals, true)
	c.Assert(val.GatewayIPs[1].IP().Equal(gatewayIP2), Equals, true)

	val, err = EgressPolicyMap.Lookup(sourceIP2, *destCIDR2)
	c.Assert(err, IsNil)

	c.Assert(val.Size, Equals, uint32(1))
	c.Assert(val.EgressIP.IP().Equal(egressIP2), Equals, true)
	c.Assert(val.GatewayIPs[0].IP().Equal(gatewayIP1), Equals, true)

	// Adding an already existing gateway to a policy should result in an error
	err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP1, gatewayIP1)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "egress policy already exists")

	// Adding a new gateway to an existing policy with a mismatching egress
	// IP should result in an error
	err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP2, gatewayIP1)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "an existing egress policy for the same source and destination IPs tuple already exists with a different egress IP")

	// Fill the policy with the maximum number of gateway
	for i := 2; i < MaxGatewayNodes; i++ {
		gatewayIP := net.ParseIP(fmt.Sprintf("5.5.5.%d", i))
		err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP1, gatewayIP)
		c.Assert(err, IsNil)
	}

	// Adding one extra gateway to the policy should result in a error
	gatewayIP := net.ParseIP("6.6.6.6")
	err = InsertEgressGateway(sourceIP1, *destCIDR1, egressIP1, gatewayIP)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, fmt.Sprintf("maximum number of gateway nodes (%d) already reached for the egress policy", MaxGatewayNodes))

	// Create 2 CT entries in the egress CT map, one related to an existing
	// policy and one unrelated
	ctKey1 := EgressCtKey4{
		tuple.TupleKey4{
			SourcePort: 1111,
			DestPort:   2222,
			NextHeader: 6,
		},
	}
	copy(ctKey1.SourceAddr[:], net.ParseIP("1.1.1.1").To4())
	copy(ctKey1.DestAddr[:], net.ParseIP("2.2.1.1").To4())

	ctVal1 := EgressCtVal4{}
	copy(ctVal1.Gateway[:], net.ParseIP("4.4.4.1").To4())

	err = EgressCtMap.Update(&ctKey1, &ctVal1, 0)
	c.Assert(err, IsNil)

	ctKey2 := EgressCtKey4{
		tuple.TupleKey4{
			SourcePort: 1111,
			DestPort:   2222,
			NextHeader: 6,
		},
	}
	copy(ctKey2.SourceAddr[:], net.ParseIP("10.10.10.10").To4())
	copy(ctKey2.DestAddr[:], net.ParseIP("20.20.20.20").To4())

	ctVal2 := EgressCtVal4{}
	copy(ctVal2.Gateway[:], net.ParseIP("40.40.40.10").To4())

	err = EgressCtMap.Update(&ctKey2, &ctVal2, 0)
	c.Assert(err, IsNil)

	// Delete the first gateway from the first policy
	err = RemoveEgressGateway(sourceIP1, *destCIDR1, gatewayIP1)
	c.Assert(err, IsNil)

	// The associated CT entry should have been deleted as well
	ctValTmp := EgressCtVal4{}
	err = EgressCtMap.Lookup(&ctKey1, &ctValTmp)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "lookup failed: key does not exist")

	// While the other (unrelated) CT entry should still be there
	err = EgressCtMap.Lookup(&ctKey2, &ctValTmp)
	c.Assert(err, IsNil)

	// Removing the same gateway again should result in an error
	err = RemoveEgressGateway(sourceIP1, *destCIDR1, gatewayIP1)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "cannot find gateway IP in egress policy")
}
