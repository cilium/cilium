// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func bmpServersByKey(servers ...*types.BMPServer) map[string]*types.BMPServer {
	out := make(map[string]*types.BMPServer, len(servers))
	for _, s := range servers {
		out[fmt.Sprintf("%s:%d", s.Address, s.Port)] = s
	}
	return out
}

func Test_BMPReconciler(t *testing.T) {
	const nodeName = "test-node"

	testCiliumNode := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}

	stationA := &types.BMPServer{
		Address:          "10.0.0.1",
		Port:             11019,
		MonitoringPolicy: types.BMPMonitoringPolicyPre,
		SysName:          nodeName,
		SysDescr:         bmpSysDescr,
	}
	stationAPost := &types.BMPServer{
		Address:          "10.0.0.1",
		Port:             11019,
		MonitoringPolicy: types.BMPMonitoringPolicyPost,
		SysName:          nodeName,
		SysDescr:         bmpSysDescr,
	}
	stationB := &types.BMPServer{
		Address:           "10.0.0.2",
		Port:              1790,
		MonitoringPolicy:  types.BMPMonitoringPolicyAll,
		StatisticsTimeout: 30,
		SysName:           nodeName,
		SysDescr:          bmpSysDescr,
	}

	tests := []struct {
		name       string
		bmpServers []v2.CiliumBGPBMPServer
		expected   map[string]*types.BMPServer
	}{
		{
			name:       "no stations",
			bmpServers: nil,
			expected:   map[string]*types.BMPServer{},
		},
		{
			name: "single station with defaults",
			bmpServers: []v2.CiliumBGPBMPServer{
				{Name: "a", PeerAddress: "10.0.0.1"},
			},
			expected: bmpServersByKey(stationA),
		},
		{
			name: "two stations with explicit options",
			bmpServers: []v2.CiliumBGPBMPServer{
				{Name: "a", PeerAddress: "10.0.0.1"},
				{
					Name:              "b",
					PeerAddress:       "10.0.0.2",
					PeerPort:          ptr.To[int32](1790),
					MonitoringPolicy:  ptr.To("all"),
					StatisticsTimeout: ptr.To[int32](30),
				},
			},
			expected: bmpServersByKey(stationA, stationB),
		},
		{
			name: "update station monitoring policy",
			bmpServers: []v2.CiliumBGPBMPServer{
				{Name: "a", PeerAddress: "10.0.0.1", MonitoringPolicy: ptr.To("post")},
			},
			expected: bmpServersByKey(stationAPost),
		},
		{
			name:       "remove all stations",
			bmpServers: nil,
			expected:   map[string]*types.BMPServer{},
		},
	}

	r := NewBMPReconciler(BMPReconcilerIn{Logger: hivetest.Logger(t)}).Reconciler.(*BMPReconciler)
	testBGPInstance := instance.NewFakeBGPInstance()
	require.NoError(t, r.Init(testBGPInstance))
	t.Cleanup(func() { r.Cleanup(testBGPInstance) })

	fakeRouter := testBGPInstance.Router.(*fake.FakeRouter)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desiredConfig := &v2.CiliumBGPNodeInstance{
				Name:       "bgp-65001",
				LocalASN:   ptr.To[int64](65001),
				BMPServers: tt.bmpServers,
			}

			// run reconciler twice to ensure idempotency
			for range 2 {
				err := r.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: desiredConfig,
					CiliumNode:    testCiliumNode,
				})
				require.NoError(t, err)
			}

			require.Equal(t, tt.expected, fakeRouter.GetBMPs())
		})
	}
}
