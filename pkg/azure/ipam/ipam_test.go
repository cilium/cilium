// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	metricsmock "github.com/cilium/cilium/operator/pkg/ipam/metrics/mock"
	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	testSubnet = &ipamTypes.Subnet{
		ID:               "subnet-1",
		VirtualNetworkID: "vpc-1",
		CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
	}

	testSubnets = []*ipamTypes.Subnet{
		{ID: "s-1", CIDR: netip.MustParsePrefix("1.1.0.0/16"), VirtualNetworkID: "vpc-1"},
		{ID: "s-2", CIDR: netip.MustParsePrefix("2.2.0.0/16"), VirtualNetworkID: "vpc-1"},
		{ID: "s-3", CIDR: netip.MustParsePrefix("3.3.3.3/16"), VirtualNetworkID: "vpc-1"},
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

func updateCiliumNode(logger *slog.Logger, cn *v2.CiliumNode, used int) *v2.CiliumNode {
	cn.Status.IPAM.Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		} else {
			return cn
		}
	}

	logging.Fatal(logger, "Not enough addresses available to simulate usage")

	return cn
}

func reachedAddressesNeeded(mngr *nodemanager.NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}

func TestMultiPoolIPRelease(t *testing.T) {
	tests := []struct {
		name        string
		instanceID  string
		interfaceID string
	}{
		{
			name:        "VMSS interface",
			instanceID:  "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1",
			interfaceID: "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11",
		},
		{
			name:        "standalone interface",
			instanceID:  "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachines/vm1",
			interfaceID: "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm1-nic",
		},
	}

	poolAllocation := func(addresses ...string) []ipamTypes.IPAMPoolAllocation {
		cidrs := make([]iputil.Prefix, 0, len(addresses))
		for _, address := range addresses {
			cidrs = append(cidrs, iputil.PrefixFrom(netip.MustParsePrefix(address+"/32")))
		}
		return []ipamTypes.IPAMPoolAllocation{{Pool: defaults.IPAMDefaultIPPool, CIDRs: cidrs}}
	}

	statusAddresses := func(cn *v2.CiliumNode) []string {
		var addresses []string
		if cn == nil {
			return nil
		}
		for _, iface := range cn.Status.Azure.Interfaces {
			for _, address := range iface.Addresses {
				addresses = append(addresses, address.IP.String())
			}
		}
		return addresses
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet})
			instances := NewInstancesManager(hivetest.Logger(t), api, true)

			iface := &types.AzureInterface{
				ID:     test.interfaceID,
				IP:     iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				Name:   "eth0",
				Subnet: types.AzureSubnet{ID: testSubnet.ID},
				Addresses: []types.AzureAddress{
					{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")), State: types.StateSucceeded},
					{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.2")), State: types.StateSucceeded},
					{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.3")), State: types.StateSucceeded},
					{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.4")), State: types.StateSucceeded},
				},
				State: types.StateSucceeded,
			}
			instanceMap := ipamTypes.NewInstanceMap()
			instanceMap.Update(test.instanceID, iface)
			api.UpdateInstances(instanceMap)
			_, err := instances.Resync(t.Context())
			require.NoError(t, err)
			api.SetMockError(apimock.ListVMNetworkInterfaces, errors.New("instance sync disabled"))

			k8sapi := newK8sMock()
			mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsmock.NewMockMetrics(), 10, true, 0, false)
			require.NoError(t, err)

			cn := newCiliumNode("node1", test.instanceID, 1, 0)
			cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{{
				Pool:   defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 4},
			}}
			cn.Spec.IPAM.Pools.Allocated = poolAllocation("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4")
			mngr.Upsert(cn)
			t.Cleanup(func() { mngr.Delete(cn) })

			updated := cn.DeepCopy()
			updated.Spec.IPAM.Pools.Requested[0].Needed.IPv4Addrs = 2
			updated.Spec.IPAM.Pools.Allocated = poolAllocation("1.1.1.2", "1.1.1.3")
			mngr.Upsert(updated)

			node := mngr.Get("node1")
			require.NotNil(t, node)
			want := []netip.Prefix{netip.MustParsePrefix("1.1.1.2/32"), netip.MustParsePrefix("1.1.1.3/32")}
			require.NoError(t, testutils.WaitUntil(func() bool {
				return len(node.Ops().GetAttachedCIDRs()) == len(want)
			}, 5*time.Second))
			require.ElementsMatch(t, want, node.Ops().GetAttachedCIDRs())

			networkInterfaces, err := api.ListAllNetworkInterfaces(t.Context())
			require.NoError(t, err)
			var cloudAddresses []string
			require.NoError(t, api.ParseInterfacesIntoInstanceMap(networkInterfaces, nil).ForeachInterface(test.instanceID, func(_, _ string, interfaceObj ipamTypes.Interface) error {
				for _, address := range interfaceObj.(*types.AzureInterface).Addresses {
					cloudAddresses = append(cloudAddresses, address.IP.String())
				}
				return nil
			}))
			require.Equal(t, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, cloudAddresses)

			statusRevision := k8sapi.statusRevision()
			mngr.Resync(t.Context(), time.Now())
			require.NoError(t, testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second))
			require.Equal(t, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, statusAddresses(k8sapi.getLatestNode("node1")))
		})
	}
}

func TestMultiPoolIPReleaseAfterIneligibleState(t *testing.T) {
	instanceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1"
	interfaceID := instanceID + "/networkInterfaces/vmss11"

	poolAllocation := func(addresses ...string) []ipamTypes.IPAMPoolAllocation {
		cidrs := make([]iputil.Prefix, 0, len(addresses))
		for _, address := range addresses {
			cidrs = append(cidrs, iputil.PrefixFrom(netip.MustParsePrefix(address+"/32")))
		}
		return []ipamTypes.IPAMPoolAllocation{{Pool: defaults.IPAMDefaultIPPool, CIDRs: cidrs}}
	}

	instanceMap := func(lastState string) *ipamTypes.InstanceMap {
		m := ipamTypes.NewInstanceMap()
		m.Update(instanceID, &types.AzureInterface{
			ID:     interfaceID,
			IP:     iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
			Name:   "eth0",
			Subnet: types.AzureSubnet{ID: testSubnet.ID},
			Addresses: []types.AzureAddress{
				{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")), State: types.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.2")), State: types.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.3")), State: types.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.4")), State: lastState},
			},
			State: types.StateSucceeded,
		})
		return m
	}

	cloudAddresses := func(api *apimock.API) []string {
		networkInterfaces, err := api.ListAllNetworkInterfaces(t.Context())
		require.NoError(t, err)
		var addresses []string
		require.NoError(t, api.ParseInterfacesIntoInstanceMap(networkInterfaces, nil).ForeachInterface(instanceID, func(_, _ string, interfaceObj ipamTypes.Interface) error {
			for _, address := range interfaceObj.(*types.AzureInterface).Addresses {
				addresses = append(addresses, address.IP.String())
			}
			return nil
		}))
		return addresses
	}

	api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet})
	instances := NewInstancesManager(hivetest.Logger(t), api, true)
	api.UpdateInstances(instanceMap(types.StateSucceeded))
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	k8sapi := newK8sMock()
	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsmock.NewMockMetrics(), 10, true, 1, false)
	require.NoError(t, err)

	cn := newCiliumNode("node1", instanceID, 1, 0)
	cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{{
		Pool:   defaults.IPAMDefaultIPPool,
		Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 4},
	}}
	cn.Spec.IPAM.Pools.Allocated = poolAllocation("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4")
	mngr.Upsert(cn)
	t.Cleanup(func() { mngr.Delete(cn) })

	updated := cn.DeepCopy()
	updated.Spec.IPAM.Pools.Requested[0].Needed.IPv4Addrs = 3
	updated.Spec.IPAM.Pools.Allocated = poolAllocation("1.1.1.1", "1.1.1.2", "1.1.1.3")
	mngr.Upsert(updated)

	api.UpdateInstances(instanceMap("failed"))
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)
	mngr.Resync(t.Context(), time.Now())
	mngr.Upsert(updated.DeepCopy())
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}, cloudAddresses(api))

	api.UpdateInstances(instanceMap(types.StateSucceeded))
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)
	mngr.Resync(t.Context(), time.Now())
	mngr.Upsert(updated.DeepCopy())

	require.NoError(t, testutils.WaitUntil(func() bool {
		return slices.Equal([]string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}, cloudAddresses(api))
	}, 10*time.Second))
}

// TestIpamPreAllocate8 tests IPAM with pre-allocation=8, min-allocate=0
func TestIpamPreAllocate8(t *testing.T) {
	preAllocate := 8
	minAllocate := 0
	toUse := 7

	api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet})
	instances := NewInstancesManager(hivetest.Logger(t), api, false)
	require.NotNil(t, instances)

	m := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		Name:          "eth0",
		SecurityGroup: "sg1",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.ID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	vm1ID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1"
	m.Update(vm1ID, resource.DeepCopy())
	api.UpdateInstances(m)

	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	k8sapi := newK8sMock()
	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	cn := newCiliumNode("node1", vm1ID, preAllocate, minAllocate)
	statusRevision := k8sapi.statusRevision()
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	// Wait for k8s status to be updated
	require.NoError(t, testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second))
	statusRevision = k8sapi.statusRevision()

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, preAllocate, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(hivetest.Logger(t), k8sapi.getLatestNode("node1"), toUse))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	// Wait for k8s status to be updated
	require.NoError(t, testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, toUse+preAllocate, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, toUse, node.Stats().IPv4.UsedIPs)
}

// TestIpamMinAllocate10 tests IPAM with pre-allocation=8, min-allocate=10
func TestIpamMinAllocate10(t *testing.T) {
	preAllocate := 8
	minAllocate := 10
	toUse := 7

	api := apimock.NewAPI([]*ipamTypes.Subnet{testSubnet})
	instances := NewInstancesManager(hivetest.Logger(t), api, false)
	require.NotNil(t, instances)

	m := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		Name:          "eth0",
		SecurityGroup: "sg1",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.ID = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	vm1ID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1"
	m.Update(vm1ID, resource.DeepCopy())
	api.UpdateInstances(m)

	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	k8sapi := newK8sMock()
	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	cn := newCiliumNode("node1", vm1ID, preAllocate, minAllocate)
	statusRevision := k8sapi.statusRevision()
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	// Wait for k8s status to be updated
	require.NoError(t, testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second))
	statusRevision = k8sapi.statusRevision()

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, minAllocate, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 10 IPs
	mngr.Upsert(updateCiliumNode(hivetest.Logger(t), k8sapi.getLatestNode("node1"), toUse))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	// Wait for k8s status to be updated
	require.NoError(t, testutils.WaitUntil(func() bool { return statusRevision < k8sapi.statusRevision() }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, toUse+preAllocate, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, toUse, node.Stats().IPv4.UsedIPs)

	quota := instances.GetPoolQuota()
	require.NotNil(t, quota)
	require.Len(t, quota, 1)
	require.Equal(t, (1<<16)-16, quota["subnet-1"].AvailableIPs)
}

type nodeState struct {
	cn           *v2.CiliumNode
	name         string
	instanceName string
}

// TestIpamManyNodes tests IP allocation of 100 nodes across 3 subnets
func TestIpamManyNodes(t *testing.T) {
	for _, test := range []struct {
		numNodes, minAllocate, concurrency int
	}{
		{numNodes: 100, minAllocate: 10, concurrency: 10},
		// The code being tested is prone to race conditions, increasing the number
		// of nodes seems to actually hide these bugs (presumably due to a higher
		// chance that racey tasks get corrected by another trigger).
		// Thus we test using a smaller node/addr domain to help catch regressions.
		{numNodes: 2, minAllocate: 1, concurrency: 10},
	} {
		t.Run(fmt.Sprintf("numNodes=%d, minAllocate=%d", test.numNodes, test.minAllocate), func(t *testing.T) {
			var (
				numNodes    = 2
				minAllocate = 1
			)
			api := apimock.NewAPI(testSubnets)
			instances := NewInstancesManager(hivetest.Logger(t), api, false)
			require.NotNil(t, instances)

			k8sapi := newK8sMock()
			metrics := metricsmock.NewMockMetrics()
			mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metrics, int64(test.concurrency), false, 0, false)
			require.NoError(t, err)
			require.NotNil(t, mngr)

			state := make([]*nodeState, numNodes)
			allInstances := ipamTypes.NewInstanceMap()

			for i := range state {
				resource := &types.AzureInterface{
					Name:          "eth0",
					SecurityGroup: "sg1",
					Subnet:        types.AzureSubnet{ID: "subnet-1"},
					Addresses: []types.AzureAddress{
						{
							IP:    iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+10))),
							State: types.StateSucceeded,
						},
					},
					State: types.StateSucceeded,
				}
				resource.ID = fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d/networkInterfaces/vmss11", i)
				allInstances.Update(fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d", i), resource.DeepCopy())
			}

			api.UpdateInstances(allInstances)
			_, err = instances.Resync(t.Context())
			require.NoError(t, err)

			for i := range state {
				state[i] = &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d", i)}
				state[i].cn = newCiliumNode(state[i].name, state[i].instanceName, 1, minAllocate)
				mngr.Upsert(state[i].cn)
			}

			for _, s := range state {
				require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second))

				node := mngr.Get(s.name)
				require.NotNil(t, node)
				if node.Stats().IPv4.AvailableIPs != minAllocate {
					t.Errorf("Node %s allocation mismatch. expected: %d allocated: %d", s.name, minAllocate, node.Stats().IPv4.AvailableIPs)
					t.Fail()
				}
				require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
			}

			// The above check returns as soon as the address requirements are met.
			// The metrics may still be outdated, resync all nodes to update
			// metrics.
			mngr.Resync(t.Context(), time.Now())
			require.Equal(t, numNodes, metrics.Nodes("total"))
			require.Equal(t, 0, metrics.Nodes("in-deficit"))
			require.Equal(t, 0, metrics.Nodes("at-capacity"))

			// All subnets must have been used for allocation
			for _, subnet := range subnets {
				require.NotEqual(t, 0, metrics.GetAllocationAttempts("createInterfaceAndAllocateIP", "success", subnet.ID))
				require.NotEqual(t, 0, metrics.IPAllocations(subnet.ID))
			}
			require.NotEqual(t, 0, metrics.ResyncCount())
		})

	}
}

func benchmarkAllocWorker(b *testing.B, workers int64, delay time.Duration, rateLimit float64, burst int) {
	api := apimock.NewAPI(testSubnets)
	api.SetDelay(apimock.AllOperations, delay)
	api.SetLimiter(rateLimit, burst)

	instances := NewInstancesManager(hivetest.Logger(b), api, false)
	require.NotNil(b, instances)

	k8sapi := newK8sMock()
	metrics := metricsmock.NewMockMetrics()
	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(b), instances, k8sapi, metrics, workers, false, 0, false)
	require.NoError(b, err)
	require.NotNil(b, mngr)

	state := make([]*nodeState, b.N)
	allInstances := ipamTypes.NewInstanceMap()

	b.ResetTimer()

	for i := range state {
		resource := &types.AzureInterface{
			Name:          "eth0",
			SecurityGroup: "sg1",
			Addresses:     []types.AzureAddress{},
			State:         types.StateSucceeded,
		}
		resource.ID = fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d/networkInterfaces/vmss11", i)
		allInstances.Update(fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d", i), resource.DeepCopy())
	}

	api.UpdateInstances(allInstances)
	_, err = instances.Resync(b.Context())
	require.NoError(b, err)

	for i := range state {
		state[i] = &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm%d", i)}
		state[i].cn = newCiliumNode(state[i].name, state[i].instanceName, 1, 10)
		mngr.Upsert(state[i].cn)
	}

restart:
	for _, s := range state {
		if !reachedAddressesNeeded(mngr, s.name, 0) {
			time.Sleep(5 * time.Millisecond)
			goto restart
		}
	}
	b.StopTimer()
}

func BenchmarkAllocDelay20Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 20*time.Millisecond, 100.0, 4)
}

func BenchmarkAllocDelay20Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 20*time.Millisecond, 100.0, 4)
}

func BenchmarkAllocDelay20Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 20*time.Millisecond, 100.0, 4)
}

func BenchmarkAllocDelay50Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 50*time.Millisecond, 100.0, 4)
}

func BenchmarkAllocDelay50Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 50*time.Millisecond, 100.0, 4)
}

func BenchmarkAllocDelay50Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 50*time.Millisecond, 100.0, 4)
}
