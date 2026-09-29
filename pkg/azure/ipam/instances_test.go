// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-3",
			CIDR:             netip.MustParsePrefix("3.3.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		},
	}
)

func iteration1(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
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
	resource.ID = "intf-1"
	instances.Update("i-1", resource.DeepCopy())

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("1.1.3.3")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.ID = "intf-3"
	instances.Update("i-2", resource.DeepCopy())

	api.UpdateInstances(instances)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
}

func iteration2(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)

	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
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
	resource.ID = "intf-1"
	instances.Update("i-1", resource.DeepCopy())

	resource = &types.AzureInterface{
		SecurityGroup: "sg2",
		Subnet:        types.AzureSubnet{ID: "subnet-3"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("3.3.3.3")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.ID = "intf-2"
	instances.Update("i-1", resource.DeepCopy())

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("1.1.3.3")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.ID = "intf-3"
	instances.Update("i-2", resource.DeepCopy())

	api.UpdateInstances(instances)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
}

func TestSubnetDiscovery(t *testing.T) {
	api := apimock.NewAPI(subnets)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api, false)
	require.NotNil(t, mngr)

	require.Nil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"])
	require.Nil(t, mngr.subnets["subnet-3"])

	iteration1(t, api, mngr)

	// Only subnets referenced by actual instances should be discovered
	// iteration1 creates instances using only subnet-1, not subnet-2 or subnet-3
	require.NotNil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"]) // Should NOT be discovered (no instances use it)
	require.Nil(t, mngr.subnets["subnet-3"]) // Should NOT be discovered (no instances use it)

	iteration2(t, api, mngr)

	// iteration2 uses subnet-1 and subnet-3, but still NOT subnet-2
	require.NotNil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"]) // Still should NOT be discovered (no instances use it)
	require.NotNil(t, mngr.subnets["subnet-3"])
}

// TestResyncInstancePreservesOtherNodesSubnets ensures that a per-instance
// resync does not evict subnets that are owned by other instances from the
// cluster-wide subnet cache. The targeted-subnet optimization in
// resyncInstance only fetches the subnets referenced by a single instance's
// interfaces; if that narrow set wholesale-replaces the global map, every
// other node's subnets disappear and PrepareIPAllocation falls through to
// the wrong subnet, which Azure rejects with
// VMScaleSetIpConfigurationsOnSameNicCannotUseDifferentSubnets.
func TestResyncInstancePreservesOtherNodesSubnets(t *testing.T) {
	api := apimock.NewAPI(subnets2)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api, false)
	require.NotNil(t, mngr)

	// Two instances using DIFFERENT subnets:
	//   vm-1 → subnet-1
	//   vm-2 → subnet-3
	instances := ipamTypes.NewInstanceMap()

	iface1 := &types.AzureInterface{
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
	iface1.ID = "intf-vm-1"
	instances.Update("vm-1", iface1.DeepCopy())

	iface2 := &types.AzureInterface{
		SecurityGroup: "sg2",
		Subnet:        types.AzureSubnet{ID: "subnet-3"},
		Addresses: []types.AzureAddress{
			{
				IP:    iputil.AddrFrom(netip.MustParseAddr("3.3.3.3")),
				State: types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	iface2.ID = "intf-vm-2"
	instances.Update("vm-2", iface2.DeepCopy())

	api.UpdateInstances(instances)

	// Initial full resync populates m.subnets with both subnets.
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
	require.NotNil(t, mngr.subnets["subnet-1"])
	require.NotNil(t, mngr.subnets["subnet-3"])

	// Per-instance resync for vm-1 only references subnet-1. It must not
	// evict subnet-3 (owned by vm-2) from the cluster-wide map.
	_, err = mngr.InstanceSync(t.Context(), "vm-1")
	require.NoError(t, err)

	require.NotNil(t, mngr.subnets["subnet-1"], "vm-1's subnet should still be present after its own per-instance resync")
	require.NotNil(t, mngr.subnets["subnet-3"], "vm-2's subnet must not be evicted by a per-instance resync of vm-1")
}

func TestExtractSubnetIDs(t *testing.T) {
	api := apimock.NewAPI(subnets)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api, false)
	require.NotNil(t, mngr)

	// Create 100 instances across only 2 different subnets to test deduplication
	instances := ipamTypes.NewInstanceMap()

	for i := range 100 {
		instanceID := fmt.Sprintf("vm-%d", i)
		interfaceID := fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/%s/networkInterfaces/eth0", instanceID)

		// Alternate between subnet-1 and subnet-3 (50 instances each)
		var subnetID string
		if i%2 == 0 {
			subnetID = "subnet-1"
		} else {
			subnetID = "subnet-3"
		}

		resource := &types.AzureInterface{
			Name:          "eth0",
			SecurityGroup: "sg1",
			Subnet:        types.AzureSubnet{ID: subnetID},
			Addresses: []types.AzureAddress{
				{
					IP:    iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", (i%254)+1, (i%254)+10))),
					State: types.StateSucceeded,
				},
			},
		}
		resource.ID = interfaceID

		instances.Update(instanceID, resource.DeepCopy())
	}

	// Extract subnet IDs and verify deduplication
	subnetIDs := mngr.extractSubnetIDs(instances)

	// Should return exactly 2 unique subnet IDs despite 100 instances
	require.Len(t, subnetIDs, 2, "Expected exactly 2 unique subnet IDs from 100 instances")

	// Verify the correct subnet IDs are present
	subnetSet := make(map[string]bool)
	for _, subnetID := range subnetIDs {
		subnetSet[subnetID] = true
	}

	require.True(t, subnetSet["subnet-1"], "Should contain subnet-1")
	require.True(t, subnetSet["subnet-3"], "Should contain subnet-3")
	require.False(t, subnetSet["subnet-2"], "Should NOT contain subnet-2 (no instances use it)")
}

type resyncGate struct {
	fetched chan struct{}
	proceed chan struct{}
}

func newResyncGate() *resyncGate {
	return &resyncGate{fetched: make(chan struct{}), proceed: make(chan struct{})}
}

func openResyncGate() *resyncGate {
	g := newResyncGate()
	close(g.proceed)
	return g
}

type gatedResyncAPI struct {
	*apimock.API
	gates chan *resyncGate

	mutex    lock.Mutex
	captures map[string]*ipamTypes.InstanceMap
}

func (a *gatedResyncAPI) capture(m *ipamTypes.InstanceMap) []*armnetwork.Interface {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	key := strconv.Itoa(len(a.captures))
	a.captures[key] = m
	return []*armnetwork.Interface{{Name: &key}}
}

func (a *gatedResyncAPI) captured(networkInterfaces []*armnetwork.Interface) *ipamTypes.InstanceMap {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.captures[*networkInterfaces[0].Name].DeepCopy()
}

func (a *gatedResyncAPI) wait() {
	g := <-a.gates
	close(g.fetched)
	<-g.proceed
}

func (a *gatedResyncAPI) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	networkInterfaces, err := a.API.ListAllNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	captured := a.capture(a.API.ParseInterfacesIntoInstanceMap(networkInterfaces, nil))
	a.wait()
	return captured, nil
}

func (a *gatedResyncAPI) ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, _ ipamTypes.SubnetMap) *ipamTypes.InstanceMap {
	return a.captured(networkInterfaces)
}

func (a *gatedResyncAPI) ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error) {
	networkInterfaces, err := a.API.ListVMNetworkInterfaces(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	m := ipamTypes.NewInstanceMap()
	m.UpdateInstance(instanceID, a.API.ParseInterfacesIntoInstance(networkInterfaces, nil))
	captured := a.capture(m)
	a.wait()
	return captured, nil
}

func (a *gatedResyncAPI) ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, _ ipamTypes.SubnetMap) *ipamTypes.Instance {
	instance := &ipamTypes.Instance{Interfaces: map[string]ipamTypes.Interface{}}
	a.captured(networkInterfaces).ForeachInterface("", func(_, interfaceID string, iface ipamTypes.Interface) error {
		instance.Interfaces[interfaceID] = iface
		return nil
	})
	return instance
}

func TestResyncKeepsReleasedInstance(t *testing.T) {
	newInterface := func(id string, addresses ...string) *types.AzureInterface {
		iface := &types.AzureInterface{ID: id, Name: id, Subnet: types.AzureSubnet{ID: "subnet-1"}, State: types.StateSucceeded}
		for _, a := range addresses {
			iface.Addresses = append(iface.Addresses, types.AzureAddress{IP: iputil.AddrFrom(netip.MustParseAddr(a)), State: types.StateSucceeded})
		}
		return iface
	}
	setCloud := func(api *gatedResyncAPI, ifaces ...*types.AzureInterface) {
		m := ipamTypes.NewInstanceMap()
		for _, iface := range ifaces {
			m.Update("vm-1", iface)
		}
		api.UpdateInstances(m)
	}
	cached := func(mngr *InstancesManager) map[string][]string {
		mngr.mutex.RLock()
		defer mngr.mutex.RUnlock()
		out := map[string][]string{}
		mngr.instances.ForeachInterface("vm-1", func(_, interfaceID string, iface ipamTypes.Interface) error {
			out[interfaceID] = []string{}
			for _, address := range iface.(*types.AzureInterface).Addresses {
				out[interfaceID] = append(out[interfaceID], address.IP.String())
			}
			slices.Sort(out[interfaceID])
			return nil
		})
		return out
	}
	hasMarker := func(mngr *InstancesManager) bool {
		mngr.mutex.RLock()
		defer mngr.mutex.RUnlock()
		_, ok := mngr.released["vm-1"]
		return ok
	}
	released := []netip.Addr{netip.MustParseAddr("1.1.1.3")}
	setup := func(t *testing.T) (*gatedResyncAPI, *InstancesManager) {
		api := &gatedResyncAPI{
			API:      apimock.NewAPI(subnets),
			gates:    make(chan *resyncGate, 2),
			captures: map[string]*ipamTypes.InstanceMap{},
		}
		setCloud(api, newInterface("nic-a", "1.1.1.2", "1.1.1.3"))
		mngr := NewInstancesManager(hivetest.Logger(t), api, false)
		api.gates <- openResyncGate()
		_, err := mngr.Resync(t.Context())
		require.NoError(t, err)
		return api, mngr
	}
	runBlocked := func(t *testing.T, api *gatedResyncAPI, fn func() error) (*resyncGate, chan error) {
		g := newResyncGate()
		api.gates <- g
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case <-g.fetched:
		case err := <-done:
			t.Fatalf("returned before fetching: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for fetch")
		}
		return g, done
	}

	t.Run("full resync", func(t *testing.T) {
		api, mngr := setup(t)

		g, done := runBlocked(t, api, func() error { _, err := mngr.Resync(t.Context()); return err })
		setCloud(api, newInterface("nic-a", "1.1.1.2"))
		mngr.removeIPsFromInterface("vm-1", "nic-a", released)
		close(g.proceed)
		require.NoError(t, <-done)
		require.Equal(t, map[string][]string{"nic-a": {"1.1.1.2"}}, cached(mngr))
		require.True(t, hasMarker(mngr))

		setCloud(api, newInterface("nic-a", "1.1.1.2", "1.1.1.9"))
		api.gates <- openResyncGate()
		_, err := mngr.Resync(t.Context())
		require.NoError(t, err)
		require.Equal(t, map[string][]string{"nic-a": {"1.1.1.2", "1.1.1.9"}}, cached(mngr))
		require.False(t, hasMarker(mngr))
	})

	t.Run("missing interface", func(t *testing.T) {
		api, mngr := setup(t)
		setCloud(api, newInterface("nic-a", "1.1.1.2", "1.1.1.3"), newInterface("nic-b", "1.1.1.5"))

		g, done := runBlocked(t, api, func() error { _, err := mngr.Resync(t.Context()); return err })
		mngr.removeIPsFromInterface("vm-1", "nic-a", released)
		close(g.proceed)
		require.NoError(t, <-done)
		require.Equal(t, map[string][]string{"nic-a": {"1.1.1.2"}}, cached(mngr))
	})

	t.Run("overlapping instance syncs", func(t *testing.T) {
		api, mngr := setup(t)

		earlier, earlierDone := runBlocked(t, api, func() error { _, err := mngr.InstanceSync(t.Context(), "vm-1"); return err })
		setCloud(api, newInterface("nic-a", "1.1.1.2"))
		mngr.removeIPsFromInterface("vm-1", "nic-a", released)

		setCloud(api, newInterface("nic-a", "1.1.1.2", "1.1.1.9"))
		later, laterDone := runBlocked(t, api, func() error { _, err := mngr.InstanceSync(t.Context(), "vm-1"); return err })
		close(later.proceed)
		require.NoError(t, <-laterDone)
		require.Equal(t, map[string][]string{"nic-a": {"1.1.1.2", "1.1.1.9"}}, cached(mngr))

		close(earlier.proceed)
		require.NoError(t, <-earlierDone)
		require.Equal(t, map[string][]string{"nic-a": {"1.1.1.2", "1.1.1.9"}}, cached(mngr))
		require.True(t, hasMarker(mngr))
	})
}
