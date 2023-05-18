// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"testing"
	"time"

	check "github.com/cilium/checkmate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type IPAMSuite struct{}

var _ = check.Suite(&IPAMSuite{})

var (
	testSubnet = &ipamTypes.Subnet{
		ID:               "subnet-1",
		VirtualNetworkID: "vpc-1",
		CIDR:             cidr.MustParseCIDR("1.1.0.0/16"),
	}

	testSubnets = []*ipamTypes.Subnet{
		{ID: "s-1", CIDR: cidr.MustParseCIDR("1.1.0.0/16"), VirtualNetworkID: "vpc-1"},
		{ID: "s-2", CIDR: cidr.MustParseCIDR("2.2.0.0/16"), VirtualNetworkID: "vpc-1"},
		{ID: "s-3", CIDR: cidr.MustParseCIDR("3.3.3.3/16"), VirtualNetworkID: "vpc-1"},
	}

	testVnet = &ipamTypes.VirtualNetwork{
		ID: "vpc-1",
	}
)

type k8sMock struct {
	mutex            lock.RWMutex
	specRev          int
	statusRev        int
	latestCiliumNode map[string]*v2.CiliumNode
}

func newK8sMock() *k8sMock {
	return &k8sMock{
		latestCiliumNode: map[string]*v2.CiliumNode{},
	}
}

func (k *k8sMock) Create(node *v2.CiliumNode) (*v2.CiliumNode, error) {
	k.mutex.Lock()
	k.specRev++
	k.latestCiliumNode[node.Name] = node
	k.mutex.Unlock()
	return nil, nil
}

func (k *k8sMock) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	k.mutex.Lock()
	k.specRev++
	k.latestCiliumNode[node.Name] = node
	k.mutex.Unlock()
	return nil, nil
}

func (k *k8sMock) statusRevision() int {
	k.mutex.RLock()
	defer k.mutex.RUnlock()
	return k.statusRev
}

func (k *k8sMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	k.mutex.Lock()
	k.statusRev++
	k.latestCiliumNode[node.Name] = node
	k.mutex.Unlock()
	return nil, nil
}

func (k *k8sMock) getLatestNode(name string) *v2.CiliumNode {
	k.mutex.RLock()
	defer k.mutex.RUnlock()
	return k.latestCiliumNode[name]
}

func (k *k8sMock) Get(node string) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func newCiliumNode(node, instanceID string, preAllocate, minAllocate int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			InstanceID: instanceID,
			IPAM: ipamTypes.IPAMSpec{
				Pool:        ipamTypes.AllocationMap{},
				PreAllocate: preAllocate,
				MinAllocate: minAllocate,
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used: ipamTypes.AllocationMap{},
			},
		},
	}

	return cn
}

func updateCiliumNode(cn *v2.CiliumNode, used int) *v2.CiliumNode {
	cn.Status.IPAM.Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		} else {
			return cn
		}
	}

	log.Fatalf("Not enough adddresses available to simulate usage")

	return cn
}

func reachedAddressesNeeded(mngr *ipam.NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}

// TestIpamPreAllocate8 tests IPAM with pre-allocation=8, min-allocate=0
func (e *IPAMSuite) TestIpamPreAllocate8(c *check.C) {
	preAllocate := 8
	minAllocate := 0
	toUse := 7

	api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVnet})
	instances := NewInstancesManager(api)
	c.Assert(instances, check.Not(check.IsNil))

	m := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		Name:          "eth0",
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11")
	m.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	api.UpdateInstances(m)

	instances.Resync(context.TODO())

	k8sapi := newK8sMock()
	mngr, err := ipam.NewNodeManager(instances, k8sapi, metricsmock.NewMockMetrics(), 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	cn := newCiliumNode("node1", "vm1", preAllocate, minAllocate)
	statusRevision := k8sapi.statusRevision()
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)
	// Wait for k8s status to be updated
	c.Assert(testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second), check.IsNil)
	statusRevision = k8sapi.statusRevision()

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, preAllocate)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 7 out of 8 IPs
	mngr.Update(updateCiliumNode(k8sapi.getLatestNode("node1"), toUse))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)
	// Wait for k8s status to be updated
	c.Assert(testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, toUse+preAllocate)
	c.Assert(node.Stats().UsedIPs, check.Equals, toUse)
}

// TestIpamMinAllocate10 tests IPAM with pre-allocation=8, min-allocate=10
func (e *IPAMSuite) TestIpamMinAllocate10(c *check.C) {
	preAllocate := 8
	minAllocate := 10
	toUse := 7

	api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVnet})
	instances := NewInstancesManager(api)
	c.Assert(instances, check.Not(check.IsNil))

	m := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		Name:          "eth0",
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11")
	m.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	api.UpdateInstances(m)

	instances.Resync(context.TODO())

	k8sapi := newK8sMock()
	mngr, err := ipam.NewNodeManager(instances, k8sapi, metricsmock.NewMockMetrics(), 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	cn := newCiliumNode("node1", "vm1", preAllocate, minAllocate)
	statusRevision := k8sapi.statusRevision()
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)
	// Wait for k8s status to be updated
	c.Assert(testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second), check.IsNil)
	statusRevision = k8sapi.statusRevision()

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, minAllocate)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 7 out of 10 IPs
	mngr.Update(updateCiliumNode(k8sapi.getLatestNode("node1"), toUse))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)
	// Wait for k8s status to be updated
	c.Assert(testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, toUse+preAllocate)
	c.Assert(node.Stats().UsedIPs, check.Equals, toUse)

	quota := instances.GetPoolQuota()
	c.Assert(len(quota), check.Equals, 1)
	c.Assert(quota["subnet-1"].AvailableIPs, check.Equals, (1<<16)-16)
}

type nodeState struct {
	cn           *v2.CiliumNode
	name         string
	instanceName string
}

// TestIpamManyNodes tests IP allocation of 100 nodes across 3 subnets
func (e *IPAMSuite) TestIpamManyNodes(c *check.C) {
	const (
		numNodes    = 100
		minAllocate = 10
	)

	api := apimock.NewAPI(testSubnets, []*ipamTypes.VirtualNetwork{testVnet})
	instances := NewInstancesManager(api)
	c.Assert(instances, check.Not(check.IsNil))

	k8sapi := newK8sMock()
	metrics := metricsmock.NewMockMetrics()
	mngr, err := ipam.NewNodeManager(instances, k8sapi, metrics, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, numNodes)
	allInstances := ipamTypes.NewInstanceMap()

	for i := range state {
		resource := &types.AzureInterface{
			Name:          "eth0",
			SecurityGroup: "sg1",
			Addresses:     []types.AzureAddress{},
			State:         types.StateSucceeded,
		}
		resource.SetID(fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d/networkInterfaces/vmss11", i))
		allInstances.Update(fmt.Sprintf("vm%d", i), ipamTypes.InterfaceRevision{
			Resource: resource.DeepCopy(),
		})
	}

	api.UpdateInstances(allInstances)
	instances.Resync(context.TODO())

	for i := range state {
		state[i] = &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("vm%d", i)}
		state[i].cn = newCiliumNode(state[i].name, state[i].instanceName, 1, minAllocate)
		mngr.Update(state[i].cn)
	}

	for _, s := range state {
		c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second), check.IsNil)

		node := mngr.Get(s.name)
		c.Assert(node, check.Not(check.IsNil))
		if node.Stats().AvailableIPs != minAllocate {
			c.Errorf("Node %s allocation mismatch. expected: %d allocated: %d", s.name, minAllocate, node.Stats().AvailableIPs)
			c.Fail()
		}
		c.Assert(node.Stats().UsedIPs, check.Equals, 0)
	}

	// The above check returns as soon as the address requirements are met.
	// The metrics may still be outdated, resync all nodes to update
	// metrics.
	mngr.Resync(context.TODO(), time.Now())

	c.Assert(metrics.Nodes("total"), check.Equals, numNodes)
	c.Assert(metrics.Nodes("in-deficit"), check.Equals, 0)
	c.Assert(metrics.Nodes("at-capacity"), check.Equals, 0)

	c.Assert(metrics.AllocatedIPs("available"), check.Equals, numNodes*minAllocate)
	c.Assert(metrics.AllocatedIPs("needed"), check.Equals, 0)
	c.Assert(metrics.AllocatedIPs("used"), check.Equals, 0)

	// All subnets must have been used for allocation
	for _, subnet := range subnets {
		c.Assert(metrics.GetAllocationAttempts("createInterfaceAndAllocateIP", "success", subnet.ID), check.Not(check.Equals), 0)
		c.Assert(metrics.IPAllocations(subnet.ID), check.Not(check.Equals), 0)
	}

	c.Assert(metrics.ResyncCount(), check.Not(check.Equals), 0)
	c.Assert(metrics.AvailableInterfaces(), check.Not(check.Equals), 0)
}

func benchmarkAllocWorker(c *check.C, workers int64, delay time.Duration, rateLimit float64, burst int) {
	api := apimock.NewAPI(testSubnets, []*ipamTypes.VirtualNetwork{testVnet})
	api.SetDelay(apimock.AllOperations, delay)
	api.SetLimiter(rateLimit, burst)

	instances := NewInstancesManager(api)
	c.Assert(instances, check.Not(check.IsNil))

	k8sapi := newK8sMock()
	metrics := metricsmock.NewMockMetrics()
	mngr, err := ipam.NewNodeManager(instances, k8sapi, metrics, workers, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, c.N)
	allInstances := ipamTypes.NewInstanceMap()

	c.ResetTimer()

	for i := range state {
		resource := &types.AzureInterface{
			Name:          "eth0",
			SecurityGroup: "sg1",
			Addresses:     []types.AzureAddress{},
			State:         types.StateSucceeded,
		}
		resource.SetID(fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d/networkInterfaces/vmss11", i))
		allInstances.Update(fmt.Sprintf("vm%d", i), ipamTypes.InterfaceRevision{
			Resource: resource.DeepCopy(),
		})
	}

	api.UpdateInstances(allInstances)
	instances.Resync(context.Background())

	for i := range state {
		state[i] = &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("vm%d", i)}
		state[i].cn = newCiliumNode(state[i].name, state[i].instanceName, 1, 10)
		mngr.Update(state[i].cn)
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

func (e *IPAMSuite) BenchmarkAllocDelay20Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 20*time.Millisecond, 100.0, 4)
}

func (e *IPAMSuite) BenchmarkAllocDelay20Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 20*time.Millisecond, 100.0, 4)
}

func (e *IPAMSuite) BenchmarkAllocDelay20Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 20*time.Millisecond, 100.0, 4)
}

func (e *IPAMSuite) BenchmarkAllocDelay50Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 50*time.Millisecond, 100.0, 4)
}

func (e *IPAMSuite) BenchmarkAllocDelay50Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 50*time.Millisecond, 100.0, 4)
}

func (e *IPAMSuite) BenchmarkAllocDelay50Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 50*time.Millisecond, 100.0, 4)
}
