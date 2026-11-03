// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	metadataMock "github.com/cilium/cilium/pkg/aws/metadata/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:                 "subnet-1",
			AvailableAddresses: 10,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-2",
			AvailableAddresses: 20,
			VirtualNetworkID:   "vpc-2",
			AvailabilityZone:   "us-east-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:                 "subnet-1",
			AvailableAddresses: 10,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-2",
			AvailableAddresses: 20,
			VirtualNetworkID:   "vpc-2",
			AvailabilityZone:   "us-east-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-3",
			AvailableAddresses: 0,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		},
	}

	vpcs = []*ipamTypes.VirtualNetwork{
		{
			ID:          "vpc-0",
			PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("1.1.0.0/16")),
		},
		{
			ID:          "vpc-1",
			PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("2.2.0.0/16")),
		},
	}
	routeTables = []*ipamTypes.RouteTable{
		{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
			},
		},
		{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-3": {},
				"subnet-4": {},
			},
		},
	}

	securityGroups = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k1": "v1"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k2": "v2"},
		},
	}

	securityGroups2 = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k1": "v1"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k2": "v2"},
		},
		{
			ID:    "sg-3",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k3": "v3"},
		},
		{
			ID:    "sg-4",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k3": "v3"},
		},
	}

	enis = map[string]apiMock.ENIMap{
		"i-1": {
			"eni-1": {
				ID:             "eni-1",
				IP:             iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				Number:         0,
				SecurityGroups: []string{"sg1", "sg2"},
				Addresses:      []iputil.Addr{},
				Subnet:         types.AwsSubnet{ID: "subnet-1"},
				VPC:            types.AwsVPC{ID: "vpc-1"},
			},
		},
		"i-2": {
			"eni-3": &types.ENI{
				ID:             "eni-3",
				IP:             iputil.AddrFrom(netip.MustParseAddr("3.3.3.3")),
				Number:         0,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []iputil.Addr{},
				Subnet:         types.AwsSubnet{ID: "subnet-2"},
				VPC:            types.AwsVPC{ID: "vpc-2"},
			},
		},
	}

	enis2 = map[string]apiMock.ENIMap{
		"i-1": {
			"eni-1": {
				ID:             "eni-1",
				IP:             iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				Number:         0,
				SecurityGroups: []string{"sg1", "sg2"},
				Addresses:      []iputil.Addr{},
				Subnet:         types.AwsSubnet{ID: "subnet-1"},
				VPC:            types.AwsVPC{ID: "vpc-1"},
			},
			"eni-2": {
				ID:             "eni-2",
				IP:             iputil.AddrFrom(netip.MustParseAddr("2.2.2.2")),
				Number:         1,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []iputil.Addr{},
				Subnet:         types.AwsSubnet{ID: "subnet-1"},
				VPC:            types.AwsVPC{ID: "vpc-1"},
			},
		},
		"i-2": {
			"eni-3": &types.ENI{
				ID:             "eni-3",
				IP:             iputil.AddrFrom(netip.MustParseAddr("3.3.3.3")),
				Number:         0,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []iputil.Addr{},
				Subnet:         types.AwsSubnet{ID: "subnet-2"},
				VPC:            types.AwsVPC{ID: "vpc-2"},
			},
		},
	}
)

func iteration1(t *testing.T, api *apiMock.API, mngr *InstancesManager) {
	api.UpdateENIs(enis)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
}

func iteration2(t *testing.T, api *apiMock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)
	api.UpdateSecurityGroups(securityGroups2)
	api.UpdateENIs(enis2)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
}

func TestGetSubnet(t *testing.T) {
	api := apiMock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)
	metadataMockapi, _ := metadataMock.NewMetadataMock()
	mngr, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMockapi)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	require.Nil(t, mngr.GetSubnet("subnet-1"))
	require.Nil(t, mngr.GetSubnet("subnet-2"))
	require.Nil(t, mngr.GetSubnet("subnet-3"))

	iteration1(t, api, mngr)

	subnet1 := mngr.GetSubnet("subnet-1")
	require.NotNil(t, subnet1)
	require.Equal(t, "subnet-1", subnet1.ID)

	subnet2 := mngr.GetSubnet("subnet-2")
	require.NotNil(t, subnet2)
	require.Equal(t, "subnet-2", subnet2.ID)

	require.Nil(t, mngr.GetSubnet("subnet-3"))

	iteration2(t, api, mngr)

	subnet1 = mngr.GetSubnet("subnet-1")
	require.NotNil(t, subnet1)
	require.Equal(t, "subnet-1", subnet1.ID)

	subnet2 = mngr.GetSubnet("subnet-2")
	require.NotNil(t, subnet2)
	require.Equal(t, "subnet-2", subnet2.ID)

	subnet3 := mngr.GetSubnet("subnet-3")
	require.NotNil(t, subnet3)
	require.Equal(t, "subnet-3", subnet3.ID)
}

func TestFindSubnetByIDs(t *testing.T) {
	api := apiMock.NewAPI(subnets2, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)
	metadataMockapi, _ := metadataMock.NewMetadataMock()
	mngr, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMockapi)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	iteration1(t, api, mngr)
	iteration2(t, api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1"})
	require.Equal(t, "subnet-1", s.ID)

	// exact match subnet-2
	s = mngr.FindSubnetByIDs("vpc-2", "us-east-1", []string{"subnet-2"})
	require.Equal(t, "subnet-2", s.ID)

	// exact match subnet-3
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-3"})
	require.Equal(t, "subnet-3", s.ID)

	// empty list shall return nil
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{}))

	// all subnet match, subnet-1 has more addresses
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1", "subnet-3"})
	require.Equal(t, "subnet-1", s.ID)

	// invalid vpc, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-unknown", "us-west-1", []string{"subnet-1"}))

	// invalid AZ, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-unknown", []string{"subnet-1"}))

	// invalid ids, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-unknown"}))
}

func TestFindSubnetByTags(t *testing.T) {
	api := apiMock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)
	metadataMockapi, _ := metadataMock.NewMetadataMock()
	mngr, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMockapi)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	iteration1(t, api, mngr)
	iteration2(t, api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "tag1"})
	require.Equal(t, "subnet-1", s.ID)

	// exact match subnet-2
	s = mngr.FindSubnetByTags("vpc-2", "us-east-1", ipamTypes.Tags{"tag1": "tag1"})
	require.Equal(t, "subnet-2", s.ID)

	// exact match subnet-3
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag2": "tag2"})
	require.Equal(t, "subnet-3", s.ID)

	// both subnet-1 and subnet-3 match, subnet-1 has more addresses
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{})
	require.Equal(t, "subnet-1", s.ID)

	// invalid vpc, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-unknown", "us-west-1", ipamTypes.Tags{"tag1": "tag1"}))

	// invalid AZ, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-1", "us-west-unknown", ipamTypes.Tags{"tag1": "tag1"}))

	// invalid tags, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "tag1", "tag2": "tag2"}))
}

func TestGetSecurityGroupByTags(t *testing.T) {
	api := apiMock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)

	metadataMockapi, _ := metadataMock.NewMetadataMock()
	mngr, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMockapi)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	sgGroups := mngr.FindSecurityGroupByTags("vpc-1", map[string]string{
		"k1": "v1",
	})
	require.Empty(t, sgGroups)

	iteration1(t, api, mngr)
	reqTags := ipamTypes.Tags{
		"k1": "v1",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 1)
	require.Equal(t, reqTags, sgGroups[0].Tags)

	iteration2(t, api, mngr)
	reqTags = ipamTypes.Tags{
		"k2": "v2",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 1)
	require.Equal(t, reqTags, sgGroups[0].Tags)

	// iteration 3
	_, err = mngr.Resync(t.Context())
	require.NoError(t, err)
	reqTags = ipamTypes.Tags{
		"k3": "v3",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 2)
	require.Equal(t, reqTags, sgGroups[0].Tags)
	require.Equal(t, reqTags, sgGroups[1].Tags)
}

// staleListingEC2API serves an eventually consistent EC2 view: once
// snapshot has been called, GetInstances and/or GetInstance return the
// captured, possibly outdated, listing.
type staleListingEC2API struct {
	EC2API

	mutex       lock.Mutex
	instances   *ipamTypes.InstanceMap
	instance    *ipamTypes.Instance
	staleFull   bool
	staleSingle bool

	// reassign, if valid, is the prefix that AssignENIPrefixes hands out,
	// as EC2 may do with a just-released prefix.
	reassign netip.Prefix
}

func (s *staleListingEC2API) AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) ([]string, error) {
	if !s.reassign.IsValid() {
		return s.EC2API.AssignENIPrefixes(ctx, eniID, prefixes)
	}
	cloud := s.EC2API.(*apiMock.API)
	instances, err := cloud.GetInstances(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	enis := map[string]apiMock.ENIMap{}
	instances.ForeachInterface("", func(instanceID, id string, iface ipamTypes.Interface) error {
		eni := iface.(*types.ENI)
		if id == eniID {
			eni.Prefixes = append(eni.Prefixes, iputil.PrefixFrom(s.reassign))
		}
		if enis[instanceID] == nil {
			enis[instanceID] = apiMock.ENIMap{}
		}
		enis[instanceID][id] = eni
		return nil
	})
	cloud.UpdateENIs(enis)
	return []string{s.reassign.String()}, nil
}

func (s *staleListingEC2API) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.staleFull {
		return s.instances.DeepCopy(), nil
	}
	return s.EC2API.GetInstances(ctx, vpcs, subnets)
}

func (s *staleListingEC2API) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.staleSingle {
		return s.instance.DeepCopy(), nil
	}
	return s.EC2API.GetInstance(ctx, vpcs, subnets, instanceID)
}

// snapshot captures the current EC2 state of instanceID.
func (s *staleListingEC2API) snapshot(t *testing.T, instanceID string) {
	t.Helper()
	instances, err := s.EC2API.GetInstances(t.Context(), nil, nil)
	require.NoError(t, err)
	instance, err := s.EC2API.GetInstance(t.Context(), nil, nil, instanceID)
	require.NoError(t, err)
	s.mutex.Lock()
	s.instances, s.instance = instances, instance
	s.mutex.Unlock()
}

// serveStale selects which listings return the snapshot.
func (s *staleListingEC2API) serveStale(full, single bool) {
	s.mutex.Lock()
	s.staleFull, s.staleSingle = full, single
	s.mutex.Unlock()
}

// newPrefixNode returns a node whose single ENI carries one /28 prefix, and
// that prefix.
func newPrefixNode(t *testing.T, instanceID string) (*Node, *apiMock.API, *staleListingEC2API, *InstancesManager, string, netip.Prefix) {
	t.Helper()

	cloud := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	stale := &staleListingEC2API{EC2API: cloud}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), stale, metadataMockapi)
	require.NoError(t, err)

	eniID, eni, err := cloud.CreateNetworkInterface(t.Context(), 0, testSubnet.ID, "primary", []string{"sg-1"}, true, false)
	require.NoError(t, err)
	require.Len(t, eni.Prefixes, 1)
	_, err = cloud.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)

	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"))
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     cn,
		instanceID: instanceID,
	}
	n.node = &mockIPAMNode{instanceID: instanceID, prefixDelegation: true, ops: n}
	n.logger.Store(n.rootLogger)
	_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)

	prefix := eni.Prefixes[0].Prefix
	require.Contains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
	return n, cloud, stale, instances, eniID, prefix
}

func cachedENIPrefixes(m *InstancesManager, instanceID, eniID string) (prefixes []netip.Prefix) {
	m.ForeachInstance(instanceID, func(_, id string, iface ipamTypes.Interface) error {
		eni, ok := iface.(*types.ENI)
		if !ok || id != eniID {
			return nil
		}
		for _, p := range eni.Prefixes {
			prefixes = append(prefixes, p.Prefix)
		}
		return nil
	})
	return prefixes
}

func releasePrefix(t *testing.T, n *Node, eniID string, prefix netip.Prefix) {
	t.Helper()
	released, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{
		InterfaceID:    eniID,
		CIDRsToRelease: []netip.Prefix{prefix},
	})
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{prefix}, released)
}

// TestReleasedPrefixNotReadvertisedByStaleListing covers issue #47910: EC2
// kept listing a /28 in the subnet-wide DescribeNetworkInterfaces for 60s
// after UnassignPrivateIpAddresses succeeded, while the per-instance query
// was already correct. The full resync replaced the cache with the stale
// listing and re-advertised the prefix in Status.ENI.
func TestReleasedPrefixNotReadvertisedByStaleListing(t *testing.T) {
	const instanceID = "i-stale-listing"

	t.Run("stale full listing after a correct per-instance sync", func(t *testing.T) {
		n, _, stale, instances, eniID, prefix := newPrefixNode(t, instanceID)
		stale.snapshot(t, instanceID)
		releasePrefix(t, n, eniID, prefix)

		// The per-instance query is already consistent.
		_, err := instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)

		// The subnet-wide listing still has the prefix.
		stale.serveStale(true, false)
		_, err = instances.Resync(t.Context())
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix,
			"a stale full listing must not bring the released prefix back")

		_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
		require.NoError(t, err)
		require.NotContains(t, n.GetAttachedCIDRs(), prefix)
	})

	t.Run("stale per-instance listing", func(t *testing.T) {
		n, _, stale, instances, eniID, prefix := newPrefixNode(t, instanceID)
		stale.snapshot(t, instanceID)
		releasePrefix(t, n, eniID, prefix)

		stale.serveStale(false, true)
		_, err := instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix,
			"a stale per-instance listing must not bring the released prefix back")
	})

	t.Run("released prefix leaves the cache at once", func(t *testing.T) {
		n, _, _, instances, eniID, prefix := newPrefixNode(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
	})
}

func tombstonedPrefixes(m *InstancesManager, eniID string) (prefixes []netip.Prefix) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if released, ok := m.releasedPrefixes[eniID]; ok {
		for p := range released.prefixes {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

func TestReleasedPrefixTombstoneLifecycle(t *testing.T) {
	const instanceID = "i-tombstone"

	t.Run("tombstone expires after the TTL", func(t *testing.T) {
		n, _, stale, instances, eniID, prefix := newPrefixNode(t, instanceID)
		stale.snapshot(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		require.Equal(t, []netip.Prefix{prefix}, tombstonedPrefixes(instances, eniID))

		stale.serveStale(true, false)
		_, err := instances.Resync(t.Context())
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)

		// Age the tombstone past the TTL. From now on EC2 listings are
		// trusted again, even this (contrived) still-stale one.
		instances.mutex.Lock()
		instances.releasedPrefixes[eniID].prefixes[prefix] = time.Now().Add(-releasedPrefixTombstoneTTL)
		instances.mutex.Unlock()

		_, err = instances.Resync(t.Context())
		require.NoError(t, err)
		require.Contains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
		require.Empty(t, tombstonedPrefixes(instances, eniID))
	})

	t.Run("re-assign via AllocateIPs clears the tombstone", func(t *testing.T) {
		n, _, stale, instances, eniID, prefix := newPrefixNode(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		require.Equal(t, []netip.Prefix{prefix}, tombstonedPrefixes(instances, eniID))

		_, _, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
		require.NoError(t, err)
		require.True(t, n.IsPrefixDelegated())

		// EC2 hands the just-released /28 back to the same ENI.
		stale.reassign = prefix
		a := &nodemanager.AllocationAction{InterfaceID: eniID}
		a.IPv4.AvailableForAllocation = 16
		require.NoError(t, n.AllocateIPs(t.Context(), a))
		require.Empty(t, tombstonedPrefixes(instances, eniID))

		_, err = instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		require.Contains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
		_, err = instances.Resync(t.Context())
		require.NoError(t, err)
		require.Contains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
	})

	t.Run("tombstone survives a transient ENI absence", func(t *testing.T) {
		n, _, stale, instances, eniID, prefix := newPrefixNode(t, instanceID)
		stale.snapshot(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		require.NotEmpty(t, tombstonedPrefixes(instances, eniID))

		// Neither listing shows the ENI for a while.
		stale.mutex.Lock()
		full, single := stale.instances.DeepCopy(), stale.instance.DeepCopy()
		stale.instances = ipamTypes.NewInstanceMap()
		stale.instance = &ipamTypes.Instance{Interfaces: map[string]ipamTypes.Interface{}}
		stale.mutex.Unlock()
		stale.serveStale(true, true)
		_, err := instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		_, err = instances.Resync(t.Context())
		require.NoError(t, err)
		require.Equal(t, []netip.Prefix{prefix}, tombstonedPrefixes(instances, eniID))

		// The ENI is listed again, with the released prefix (stale).
		stale.mutex.Lock()
		stale.instances, stale.instance = full, single
		stale.mutex.Unlock()
		_, err = instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
		_, err = instances.Resync(t.Context())
		require.NoError(t, err)
		require.NotContains(t, cachedENIPrefixes(instances, instanceID, eniID), prefix)
	})

	t.Run("expired tombstone of an absent ENI is dropped", func(t *testing.T) {
		n, cloud, _, instances, eniID, prefix := newPrefixNode(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		instances.mutex.Lock()
		instances.releasedPrefixes[eniID].prefixes[prefix] = time.Now().Add(-releasedPrefixTombstoneTTL)
		instances.mutex.Unlock()

		cloud.UpdateENIs(map[string]apiMock.ENIMap{instanceID: {}})
		_, err := instances.InstanceSync(t.Context(), instanceID)
		require.NoError(t, err)
		require.Empty(t, tombstonedPrefixes(instances, eniID))
	})

	t.Run("tombstone is dropped when the instance is deleted", func(t *testing.T) {
		n, _, _, instances, eniID, prefix := newPrefixNode(t, instanceID)
		releasePrefix(t, n, eniID, prefix)
		require.NotEmpty(t, tombstonedPrefixes(instances, eniID))

		instances.DeleteInstance(instanceID)
		require.Empty(t, tombstonedPrefixes(instances, eniID))
	})
}

// TestReleasedPrefixTombstoneLostOnRestart documents a known gap of the
// tombstones of cilium/cilium#47910: they live in the memory of the operator
// that released the prefix. A restarted operator, or a new leader, trusts
// its first EC2 listings, so a stale listing within the TTL re-advertises
// the released prefix.
func TestReleasedPrefixTombstoneLostOnRestart(t *testing.T) {
	const instanceID = "i-tombstone-restart"

	n, _, stale, _, eniID, prefix := newPrefixNode(t, instanceID)
	stale.snapshot(t, instanceID)
	releasePrefix(t, n, eniID, prefix)

	// The new leader starts while EC2 still lists the released prefix.
	stale.serveStale(true, true)
	restarted, err := NewInstancesManager(t.Context(), hivetest.Logger(t), stale, metadataMockapi)
	require.NoError(t, err)
	_, err = restarted.Resync(t.Context())
	require.NoError(t, err)
	require.Empty(t, tombstonedPrefixes(restarted, eniID))
	require.Contains(t, cachedENIPrefixes(restarted, instanceID, eniID), prefix,
		"known gap: a restarted operator has no tombstone and re-advertises the released prefix")

	// Once EC2 is consistent, the prefix disappears again.
	stale.serveStale(false, false)
	_, err = restarted.Resync(t.Context())
	require.NoError(t, err)
	require.NotContains(t, cachedENIPrefixes(restarted, instanceID, eniID), prefix)
}
