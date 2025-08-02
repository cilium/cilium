// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

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
