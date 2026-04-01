// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

type testNeededDef struct {
	available   int
	used        int
	preallocate int
	minallocate int
	maxallocate int
	result      int
}

type testExcessDef struct {
	available         int
	used              int
	preallocate       int
	minallocate       int
	maxabovewatermark int
	result            int
}

var neededDef = []testNeededDef{
	{0, 0, 0, 16, 0, 16},
	{0, 0, 8, 16, 0, 16},
	{0, 0, 16, 8, 0, 16},
	{0, 0, 16, 0, 0, 16},
	{8, 0, 0, 16, 0, 8},
	{8, 4, 8, 0, 0, 4},
	{8, 4, 8, 8, 0, 4},
	{8, 4, 8, 8, 6, 0},
	{8, 4, 8, 0, 8, 0},
	{4, 4, 8, 0, 8, 4},
}

var excessDef = []testExcessDef{
	{0, 0, 0, 16, 0, 0},
	{15, 0, 8, 16, 8, 0},
	{17, 0, 8, 16, 0, 1}, // 17 used, 8 pre-allocate, 16 min-allocate => 1 excess
	{20, 0, 8, 16, 4, 0}, // 20 used, 8 pre-allocate, 16 min-allocate, 4 max-above-watermark => 0 excess
	{21, 0, 8, 0, 4, 9},  // 21 used, 8 pre-allocate, 4 max-above-watermark => 9 excess
	{20, 0, 8, 20, 8, 0},
	{16, 1, 8, 16, 8, 0},
	{20, 4, 8, 17, 8, 0},
	{20, 4, 8, 0, 0, 8},
	{20, 4, 8, 0, 8, 0},
}

func TestCalculateNeededIPs(t *testing.T) {
	for _, d := range neededDef {
		result := calculateNeededIPs(d.available, d.used, d.preallocate, d.minallocate, d.maxallocate)
		require.Equal(t, d.result, result)
	}
}

func TestCalculateExcessIPs(t *testing.T) {
	for _, d := range excessDef {
		result := calculateExcessIPs(d.available, d.used, d.preallocate, d.minallocate, d.maxabovewatermark)
		require.Equal(t, d.result, result)
	}
}

type k8sMockNode struct{}

func (k *k8sMockNode) Update(origNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), newNode.Name)
}

func (k *k8sMockNode) UpdateStatus(origNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), newNode.Name)
}

func (k *k8sMockNode) Get(node string) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), node)
}

func (k *k8sMockNode) Create(*v2.CiliumNode) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func TestSyncToAPIServerForNonExistingNode(t *testing.T) {
	node := &Node{
		rootLogger: hivetest.Logger(t),
		name:       "test-node",
		manager: &NodeManager{
			k8sAPI: &k8sMockNode{},
		},
		logLimiter: logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		ipv4Alloc: ipAllocAttrs{
			ipsMarkedForRelease: make(map[string]time.Time),
			ipReleaseStatus:     make(map[string]string),
		},
		resource: newCiliumNode("test-node", 0, 0, 0),
		ops:      &nodeOperationsMock{},
	}
	node.updateLogger()

	require.NoError(t, node.syncToAPIServer())
}

type prefixDelegationMock struct {
	nodeOperationsMock
	prefixDelegated bool
}

func (p *prefixDelegationMock) IsPrefixDelegated() bool {
	return p.prefixDelegated
}

func TestBuildPoolAllocated(t *testing.T) {
	t.Run("no ENIs returns nil", func(t *testing.T) {
		n := &Node{ops: &nodeOperationsMock{}}
		node := &v2.CiliumNode{}
		require.Nil(t, n.buildPoolAllocated(node))
	})

	t.Run("secondary IPs as /32 CIDRs", func(t *testing.T) {
		n := &Node{ops: &prefixDelegationMock{prefixDelegated: false}}
		node := &v2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]eniTypes.ENI{
			"eni-1": {
				Addresses: []string{"10.0.0.1", "10.0.0.2"},
			},
		}

		result := n.buildPoolAllocated(node)
		require.Len(t, result, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result[0].Pool)
		require.Contains(t, result[0].CIDRs, ipamTypes.IPAMCIDR("10.0.0.1/32"))
		require.Contains(t, result[0].CIDRs, ipamTypes.IPAMCIDR("10.0.0.2/32"))
	})

	t.Run("prefix delegation writes prefixes and excludes covered addresses", func(t *testing.T) {
		n := &Node{ops: &prefixDelegationMock{prefixDelegated: true}}
		node := &v2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]eniTypes.ENI{
			"eni-1": {
				// Mimics the pkg/aws/ec2.parseENI behavior: Addresses contains the ENI secondary
				// IPs, the ENI primary if UsePrimaryAddress annd the 16 IPs expanded from the /28 prefix.
				// Prefixes contains the raw /28.
				Addresses: []string{
					"10.0.0.1", // ENI primary IP (UsePrimaryAddress)
					"10.0.0.16", "10.0.0.17", "10.0.0.18", "10.0.0.19",
					"10.0.0.20", "10.0.0.21", "10.0.0.22", "10.0.0.23",
					"10.0.0.24", "10.0.0.25", "10.0.0.26", "10.0.0.27",
					"10.0.0.28", "10.0.0.29", "10.0.0.30", "10.0.0.31",
				},
				Prefixes: []string{"10.0.0.16/28"},
			},
		}

		result := n.buildPoolAllocated(node)
		require.Len(t, result, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result[0].Pool)
		// Should contain the /28 prefix and the primary IP as /32,
		// but not the 16 expanded prefix IPs.
		require.Contains(t, result[0].CIDRs, ipamTypes.IPAMCIDR("10.0.0.16/28"))
		require.Contains(t, result[0].CIDRs, ipamTypes.IPAMCIDR("10.0.0.1/32"))
		require.Len(t, result[0].CIDRs, 2) // 1 prefix + 1 primary IP
	})

	t.Run("excluded ENIs are skipped", func(t *testing.T) {
		n := &Node{ops: &prefixDelegationMock{prefixDelegated: false}}
		node := &v2.CiliumNode{}
		node.Spec.ENI.ExcludeInterfaceTags = map[string]string{"skip": "true"}
		node.Status.ENI.ENIs = map[string]eniTypes.ENI{
			"eni-1": {
				Addresses: []string{"10.0.0.1"},
				Tags:      map[string]string{"skip": "true"},
			},
			"eni-2": {
				Addresses: []string{"10.0.0.2"},
			},
		}

		result := n.buildPoolAllocated(node)
		require.Len(t, result, 1)
		require.Len(t, result[0].CIDRs, 1)
		require.Contains(t, result[0].CIDRs, ipamTypes.IPAMCIDR("10.0.0.2/32"))
	})
}
