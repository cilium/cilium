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

package eni

import (
	"context"
	"errors"
	"fmt"
	"time"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	metricsmock "github.com/cilium/cilium/pkg/aws/eni/metrics/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/checker"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	"gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	testSubnet = &types.Subnet{
		ID:                 "s-1",
		AvailabilityZone:   "us-west-1",
		VpcID:              "vpc-1",
		AvailableAddresses: 200,
		Tags:               types.Tags{"k": "v"},
	}
	testVpc = &types.Vpc{
		ID:          "vpc-1",
		PrimaryCIDR: "10.10.0.0/16",
	}
	testSecurityGroups = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  types.Tags{"test-sg-1": "yes"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  types.Tags{"test-sg-2": "yes"},
		},
	}
	k8sapi     = &k8sMock{}
	metricsapi = metricsmock.NewMockMetrics()
	eniTags    = map[string]string{}
)

func (e *ENISuite) TestGetNodeNames(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testGetNodeNames-1", eniID1)
	c.Assert(err, check.IsNil)
	eniID2, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testGetNodeNames-2", eniID2)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())

	mngr.Update(newCiliumNode("node1", "i-testGetNodeNames-1", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0))

	names := mngr.GetNames()
	c.Assert(len(names), check.Equals, 1)
	c.Assert(names[0], check.Equals, "node1")

	mngr.Update(newCiliumNode("node2", "i-testGetNodeNames-2", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0))

	names = mngr.GetNames()
	c.Assert(len(names), check.Equals, 2)

	mngr.Delete("node1")

	names = mngr.GetNames()
	c.Assert(len(names), check.Equals, 1)
	c.Assert(names[0], check.Equals, "node2")
}

func (e *ENISuite) TestNodeManagerGet(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerGet-1", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())

	mngr.Update(newCiliumNode("node1", "i-testNodeManagerGet-1", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0))

	c.Assert(mngr.Get("node1"), check.Not(check.IsNil))
	c.Assert(mngr.Get("node2"), check.IsNil)

	mngr.Delete("node1")
	c.Assert(mngr.Get("node1"), check.IsNil)
	c.Assert(mngr.Get("node2"), check.IsNil)
}

type k8sMock struct{}

func (k *k8sMock) Update(node, origNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) UpdateStatus(node, origNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) Get(node string) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func newCiliumNode(node, instanceID, instanceType, az, vpcID string, firstAllocateIndex, preAllocate, minAllocate, available, used int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			ENI: v2.ENISpec{
				InstanceID:          instanceID,
				InstanceType:        instanceType,
				PreAllocate:         preAllocate,
				MinAllocate:         minAllocate,
				FirstInterfaceIndex: &firstAllocateIndex,
				AvailabilityZone:    az,
				VpcID:               vpcID,
			},
			IPAM: v2.IPAMSpec{
				Pool: map[string]v2.AllocationIP{},
			},
		},
		Status: v2.NodeStatus{
			IPAM: v2.IPAMStatus{
				Used: map[string]v2.AllocationIP{},
			},
		},
	}

	updateCiliumNode(cn, available, used)

	return cn
}

func newCiliumNodeWithSGTags(node, instanceID, instanceType, az, vpcID string, sgTags map[string]string, firstAllocateIndex, preAllocate, minAllocate, available, used int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			ENI: v2.ENISpec{
				InstanceID:          instanceID,
				InstanceType:        instanceType,
				PreAllocate:         preAllocate,
				MinAllocate:         minAllocate,
				FirstInterfaceIndex: &firstAllocateIndex,
				AvailabilityZone:    az,
				VpcID:               vpcID,
				SecurityGroupTags:   sgTags,
			},
			IPAM: v2.IPAMSpec{
				Pool: map[string]v2.AllocationIP{},
			},
		},
		Status: v2.NodeStatus{
			IPAM: v2.IPAMStatus{
				Used: map[string]v2.AllocationIP{},
			},
		},
	}

	updateCiliumNode(cn, available, used)

	return cn
}

func updateCiliumNode(cn *v2.CiliumNode, available, used int) *v2.CiliumNode {
	cn.Spec.IPAM.Pool = map[string]v2.AllocationIP{}
	for i := 0; i < used; i++ {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = v2.AllocationIP{Resource: "foo"}
	}

	cn.Status.IPAM.Used = map[string]v2.AllocationIP{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			delete(cn.Spec.IPAM.Pool, ip)
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		}
	}

	return cn
}

func reachedAddressesNeeded(mngr *NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.getNeededAddresses() == needed
	}
	return
}

// TestNodeManagerDefaultAllocation tests allocation with default parameters
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 0
// - PreAllocate 0 (default: 8)
func (e *ENISuite) TestNodeManagerDefaultAllocation(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerDefaultAllocation-0", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", "i-testNodeManagerDefaultAllocation-0", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 8)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Use 7 out of 8 IPs
	mngr.Update(updateCiliumNode(cn, 8, 7))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 15)
	c.Assert(node.stats.usedIPs, check.Equals, 7)
}

// TestNodeManagerENIWithSGTags tests ENI allocation + association with a SG based on tags
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 0
// - PreAllocate 0 (default: 8)
func (e *ENISuite) TestNodeManagerENIWithSGTags(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerDefaultAllocation-0", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node wait for IPs to become available
	sgTags := map[string]string{
		"test-sg-1": "yes",
	}
	cn := newCiliumNodeWithSGTags("node1", "i-testNodeManagerDefaultAllocation-0", "m4.large", "us-west-1", "vpc-1", sgTags, 0, 0, 0, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 8)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Use 7 out of 8 IPs
	mngr.Update(updateCiliumNode(cn, 8, 7))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 15)
	c.Assert(node.stats.usedIPs, check.Equals, 7)

	// At this point we have 2 enis, make a local copy
	// and remove eth0 from the map
	enis := node.ENIs()
	delete(enis, eniID1)
	for _, eni := range enis {
		c.Assert(eni.SecurityGroups, checker.DeepEquals, []string{"sg-1"})
	}
}

// TestNodeManagerMinAllocate20 tests MinAllocate without PreAllocate
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 10
// - PreAllocate -1
func (e *ENISuite) TestNodeManagerMinAllocate20(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerMinAllocate20-1", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node2", "i-testNodeManagerMinAllocate20-1", "m5.4xlarge", "us-west-1", "vpc-1", 0, -1, 10, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 10)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	mngr.Update(updateCiliumNode(cn, 10, 8))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 10)
	c.Assert(node.stats.usedIPs, check.Equals, 8)

	// Change MinAllocate to 20
	cn = newCiliumNode("node2", "i-testNodeManagerMinAllocate20-1", "m5.4xlarge", "us-west-1", "vpc-1", 0, 0, 20, 10, 8)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 20)
	c.Assert(node.stats.usedIPs, check.Equals, 8)
}

// TestNodeManagerMinAllocateAndPreallocate tests MinAllocate in combination with PreAllocate
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 10
// - PreAllocate 1
func (e *ENISuite) TestNodeManagerMinAllocateAndPreallocate(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerMinAllocateAndPreallocate-1", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", "i-testNodeManagerMinAllocateAndPreallocate-1", "m4.large", "us-west-1", "vpc-1", 0, 1, 10, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 10)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Use 9 out of 10 IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 10, 9))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 10)
	c.Assert(node.stats.usedIPs, check.Equals, 9)

	// Use 10 out of 10 IPs, PreAllocate 1 must kick in and allocate an additional IP
	mngr.Update(updateCiliumNode(cn, 10, 10))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 11)
	c.Assert(node.stats.usedIPs, check.Equals, 10)

	// Release some IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 10, 8))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 11)
	c.Assert(node.stats.usedIPs, check.Equals, 8)
}

// TestNodeManagerReleaseAddress tests PreAllocate, MinAllocate and MaxAboveWatermark
// when release excess IP is enabled
//
// - m4.large (4x ENIs, 4x15 IPs)
// - MinAllocate 15
// - PreAllocate 4
// - MaxAboveWatermark 4
// - FirstInterfaceIndex 1
func (e *ENISuite) TestNodeManagerReleaseAddress(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerReleaseAddress-1", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	option.Config.AwsReleaseExcessIps = true

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", "i-testNodeManagerReleaseAddress-1", "m4.xlarge", "us-west-1", "vpc-1", 0, 4, 15, 0, 0)
	cn.Spec.ENI.MaxAboveWatermark = 4
	firstInterfaceIndex := 1
	cn.Spec.ENI.FirstInterfaceIndex = &firstInterfaceIndex
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 15)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Use 11 out of 15 IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 15, 11))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 15)
	c.Assert(node.stats.usedIPs, check.Equals, 11)

	// Use 15 out of 15 IPs, PreAllocate 4 + MaxAboveWatermark must kick in and allocate 8 additional IPs
	mngr.Update(updateCiliumNode(cn, 15, 15))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 23)
	c.Assert(node.stats.usedIPs, check.Equals, 15)

	// Free some IPs, 5 excess IPs appears but only be released at interval based resync, so expect timeout here
	mngr.Update(updateCiliumNode(cn, 23, 10))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 2*time.Second), check.Not(check.IsNil))
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 23)
	c.Assert(node.stats.usedIPs, check.Equals, 10)

	// Trigger resync manually, excess IPs should be released
	node = mngr.Get("node3")
	node.resource.Status.ENI.ENIs = node.enis
	syncTime := instances.Resync(context.TODO())
	mngr.resyncNode(context.TODO(), node, &resyncStats{}, syncTime)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 18)
	c.Assert(node.stats.usedIPs, check.Equals, 10)

	option.Config.AwsReleaseExcessIps = false
}

// TestNodeManagerExceedENICapacity tests exceeding ENI capacity
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 20
// - PreAllocate 8
func (e *ENISuite) TestNodeManagerExceedENICapacity(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerExceedENICapacity-1", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", "i-testNodeManagerExceedENICapacity-1", "m4.large", "us-west-1", "vpc-1", 0, 8, 20, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 20)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Use 16 out of 20 IPs, we should reach 4 addresses needed but never 0 addresses needed
	mngr.Update(updateCiliumNode(cn, 20, 16))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 4) }, 5*time.Second), check.IsNil)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.Not(check.IsNil))

	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 20)
	c.Assert(node.stats.usedIPs, check.Equals, 16)
}

type nodeState struct {
	cn           *v2.CiliumNode
	name         string
	instanceName string
}

// TestNodeManagerManyNodes tests IP allocation of 100 nodes across 3 subnets
//
// - m4.large (2x ENIs, 2x10 IPs)
// - MinAllocate 10
// - PreAllocate 1
func (e *ENISuite) TestNodeManagerManyNodes(c *check.C) {
	const (
		numNodes    = 100
		minAllocate = 10
	)

	subnets := []*types.Subnet{
		{ID: "mgmt-1", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 100},
		{ID: "s-1", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 400},
		{ID: "s-2", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 400},
		{ID: "s-3", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 400},
	}

	ec2api := ec2mock.NewAPI(subnets, []*types.Vpc{testVpc}, testSecurityGroups)
	metricsapi := metricsmock.NewMockMetrics()
	instancesManager := NewInstancesManager(ec2api, metricsapi)
	mngr, err := NewNodeManager(instancesManager, ec2api, k8sapi, metricsapi, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, numNodes)

	for i := range state {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "mgmt-1", "desc", []string{"sg1", "sg2"})
		c.Assert(err, check.IsNil)
		_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, fmt.Sprintf("i-testNodeManagerManyNodes-%d", i), eniID)
		c.Assert(err, check.IsNil)
		instancesManager.Resync(context.TODO())
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-testNodeManagerManyNodes-%d", i)}
		s.cn = newCiliumNode(s.name, s.instanceName, "m4.large", "us-west-1", "vpc-1", 0, 1, minAllocate, 0, 0)
		firstInterfaceIndex := 1
		s.cn.Spec.ENI.FirstInterfaceIndex = &firstInterfaceIndex
		state[i] = s
		mngr.Update(s.cn)
	}

	for _, s := range state {
		c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second), check.IsNil)

		node := mngr.Get(s.name)
		c.Assert(node, check.Not(check.IsNil))
		if node.stats.availableIPs != minAllocate {
			c.Errorf("Node %s allocation mismatch. expected: %d allocated: %d", s.name, minAllocate, node.stats.availableIPs)
			c.Fail()
		}
		c.Assert(node.stats.usedIPs, check.Equals, 0)
	}

	// The above check returns as soon as the address requirements are met.
	// The metrics may still be oudated, resync all nodes to update
	// metrics.
	mngr.Resync(context.TODO(), time.Now())

	c.Assert(metricsapi.Nodes("total"), check.Equals, numNodes)
	c.Assert(metricsapi.Nodes("in-deficit"), check.Equals, 0)
	c.Assert(metricsapi.Nodes("at-capacity"), check.Equals, 0)

	c.Assert(metricsapi.AllocatedIPs("available"), check.Equals, numNodes*minAllocate)
	c.Assert(metricsapi.AllocatedIPs("needed"), check.Equals, 0)
	c.Assert(metricsapi.AllocatedIPs("used"), check.Equals, 0)

	// All subnets must have been used for allocation
	for _, subnet := range subnets {
		c.Assert(metricsapi.ENIAllocationAttempts("success", subnet.ID), check.Not(check.Equals), 0)
		c.Assert(metricsapi.IPAllocations(subnet.ID), check.Not(check.Equals), 0)
	}

	c.Assert(metricsapi.ResyncCount(), check.Not(check.Equals), 0)
	c.Assert(metricsapi.AvailableENIs(), check.Not(check.Equals), 0)
}

// TestNodeManagerInstanceNotRunning verifies that allocation correctly detects
// instances which are no longer running
func (e *ENISuite) TestNodeManagerInstanceNotRunning(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	metricsMock := metricsmock.NewMockMetrics()
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testNodeManagerInstanceNotRunning-0", eniID1)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsMock, 10, eniTags)
	ec2api.SetMockError(ec2mock.AttachNetworkInterface, errors.New("foo is not 'running' foo"))
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, ENI attachement will fail
	cn := newCiliumNode("node1", "i-testNodeManagerInstanceNotRunning-0", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0)
	firstInterfaceIndex := 1
	cn.Spec.ENI.FirstInterfaceIndex = &firstInterfaceIndex

	mngr.Update(cn)

	// Wait for node to be declared notRunning
	c.Assert(testutils.WaitUntil(func() bool {
		if n := mngr.Get("node1"); n != nil {
			return n.instanceNotRunning
		}
		return false
	}, 5*time.Second), check.IsNil)

	// Metric should not indicate failure
	c.Assert(metricsMock.ENIAllocationAttempts("ENI attachment failed", testSubnet.ID), check.Equals, int64(0))

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 0)
	c.Assert(node.stats.usedIPs, check.Equals, 0)
}

// TestInstanceBeenDeleted verifies that instance deletion is correctly detected
// and no further action is taken
//
// - m4.large (2x ENIs, 2x10 IPs)
func (e *ENISuite) TestInstanceBeenDeleted(c *check.C) {
	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet}, []*types.Vpc{testVpc}, testSecurityGroups)
	metricsMock := metricsmock.NewMockMetrics()
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	eniID1, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, "i-testInstanceBeenDeleted-0", eniID1)
	c.Assert(err, check.IsNil)
	eniID2, _, err := ec2api.CreateNetworkInterface(context.TODO(), 8, "s-1", "desc", []string{"sg1", "sg2"})
	c.Assert(err, check.IsNil)
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 1, "i-testInstanceBeenDeleted-0", eniID2)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsMock, 10, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	cn := newCiliumNode("node1", "i-testInstanceBeenDeleted-0", "m4.large", "us-west-1", "vpc-1", 0, 0, 0, 0, 0)
	firstInterfaceIndex := 1
	cn.Spec.ENI.FirstInterfaceIndex = &firstInterfaceIndex
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.availableIPs, check.Equals, 8)
	c.Assert(node.stats.usedIPs, check.Equals, 0)

	// Delete all enis attached to instance, this mocks the operation of
	// deleting the instance. The deletion should be detected.
	err = ec2api.DeleteNetworkInterface(context.TODO(), eniID1)
	c.Assert(err, check.IsNil)
	err = ec2api.DeleteNetworkInterface(context.TODO(), eniID2)
	c.Assert(err, check.IsNil)
	instances.Resync(context.TODO())
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.stats.neededIPs, check.Equals, 0)
	c.Assert(node.stats.excessIPs, check.Equals, 0)
}

func benchmarkAllocWorker(c *check.C, workers int64, delay time.Duration, rateLimit float64, burst int) {
	testSubnet1 := &types.Subnet{ID: "s-1", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 1000000}
	testSubnet2 := &types.Subnet{ID: "s-2", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 1000000}
	testSubnet3 := &types.Subnet{ID: "s-3", AvailabilityZone: "us-west-1", VpcID: "vpc-1", AvailableAddresses: 1000000}

	ec2api := ec2mock.NewAPI([]*types.Subnet{testSubnet1, testSubnet2, testSubnet3}, []*types.Vpc{testVpc}, testSecurityGroups)
	ec2api.SetDelay(ec2mock.AllOperations, delay)
	ec2api.SetLimiter(rateLimit, burst)
	instances := NewInstancesManager(ec2api, metricsapi)
	c.Assert(instances, check.Not(check.IsNil))
	mngr, err := NewNodeManager(instances, ec2api, k8sapi, metricsapi, workers, eniTags)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, c.N)

	c.ResetTimer()
	for i := range state {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 1, "s-1", "desc", []string{"sg1", "sg2"})
		c.Assert(err, check.IsNil)
		_, err = ec2api.AttachNetworkInterface(context.TODO(), 0, fmt.Sprintf("i-benchmarkAllocWorker-%d", i), eniID)
		c.Assert(err, check.IsNil)
		instances.Resync(context.TODO())
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-benchmarkAllocWorker-%d", i)}
		s.cn = newCiliumNode(s.name, s.instanceName, "m4.large", "us-west-1", "vpc-1", 0, 1, 10, 0, 0)
		state[i] = s
		mngr.Update(s.cn)
	}

restart:
	for _, s := range state {
		if !reachedAddressesNeeded(mngr, s.name, 0) {
			time.Sleep(5 * time.Millisecond)
			goto restart
		}
	}
	c.StopTimer()

}

func (e *ENISuite) BenchmarkAllocDelay20Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 20*time.Millisecond, 100.0, 4)
}
func (e *ENISuite) BenchmarkAllocDelay20Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 20*time.Millisecond, 100.0, 4)
}
func (e *ENISuite) BenchmarkAllocDelay20Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 20*time.Millisecond, 100.0, 4)
}
func (e *ENISuite) BenchmarkAllocDelay50Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 50*time.Millisecond, 100.0, 4)
}
func (e *ENISuite) BenchmarkAllocDelay50Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 50*time.Millisecond, 100.0, 4)
}
func (e *ENISuite) BenchmarkAllocDelay50Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 50*time.Millisecond, 100.0, 4)
}
