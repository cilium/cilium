// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
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

type releaseOpsMock struct {
	nodeOperationsMock
	prefixes, ips []string
}

func (m *releaseOpsMock) ReleaseIPPrefixes(_ context.Context, r *ReleaseAction) error {
	m.prefixes = append(m.prefixes, r.IPPrefixesToRelease...)
	return nil
}

func (m *releaseOpsMock) ReleaseIPs(_ context.Context, r *ReleaseAction) error {
	m.ips = append(m.ips, r.IPsToRelease...)
	return nil
}

func TestHandleIPReleasePrefixes(t *testing.T) {
	prefixIPs := func(base string) (ips []string) {
		for i := range 16 {
			ips = append(ips, fmt.Sprintf("%s.%d", base, 16+i))
		}
		return ips
	}
	prefixA, ipsA := "10.0.0.16/28", prefixIPs("10.0.0")
	prefixB, ipsB := "10.0.1.16/28", prefixIPs("10.0.1")
	const secondary = "10.0.2.5"

	tests := []struct {
		name             string
		prefixes         []string
		ips              []string
		agent            map[string]ipamTypes.IPReleaseStatus // defaults to ready-for-release
		releasedPrefixes []string
		releasedIPs      []string
	}{
		{
			name:     "do-not-release IP withholds prefix",
			prefixes: []string{prefixA},
			ips:      ipsA,
			agent:    map[string]ipamTypes.IPReleaseStatus{ipsA[9]: ipamOption.IPAMDoNotRelease},
		},
		{
			name:     "unanswered IP withholds prefix",
			prefixes: []string{prefixA},
			ips:      ipsA,
			agent:    map[string]ipamTypes.IPReleaseStatus{ipsA[9]: ipamOption.IPAMMarkForRelease},
		},
		{
			name:             "fully acknowledged prefix is released",
			prefixes:         []string{prefixA, prefixB},
			ips:              append(append(append([]string{}, ipsA...), ipsB...), secondary),
			agent:            map[string]ipamTypes.IPReleaseStatus{ipsB[0]: ipamOption.IPAMDoNotRelease},
			releasedPrefixes: []string{prefixA},
			releasedIPs:      append(append([]string{}, ipsA...), secondary),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &releaseOpsMock{}
			n := &Node{
				rootLogger:           hivetest.Logger(t),
				ops:                  ops,
				manager:              &NodeManager{metricsAPI: metricsmock.NewMockMetrics()},
				resource:             &v2.CiliumNode{},
				excessIPReleaseDelay: time.Second,
				ipv4Alloc: ipAllocAttrs{
					ipsMarkedForRelease: map[string]time.Time{},
					ipReleaseStatus:     map[string]string{},
				},
			}
			n.updateLogger()
			n.resource.Status.IPAM.ReleaseIPs = map[string]ipamTypes.IPReleaseStatus{}
			for _, ip := range tt.ips {
				status, ok := tt.agent[ip]
				if !ok {
					status = ipamOption.IPAMReadyForRelease
				}
				n.ipv4Alloc.ipsMarkedForRelease[ip] = time.Now().Add(-time.Hour)
				n.ipv4Alloc.ipReleaseStatus[ip] = string(status)
				n.resource.Status.IPAM.ReleaseIPs[ip] = status
			}

			_, err := n.handleIPRelease(context.Background(), &maintenanceAction{release: &ReleaseAction{
				InterfaceID:         "eni-1",
				IPsToRelease:        tt.ips,
				IPPrefixesToRelease: tt.prefixes,
			}})
			require.NoError(t, err)
			require.Equal(t, tt.releasedPrefixes, ops.prefixes)
			require.ElementsMatch(t, tt.releasedIPs, ops.ips)
		})
	}
}
