// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

func TestDisableStatusReport(t *testing.T) {
	ctx := context.TODO()
	logger := hivetest.Logger(t)

	var cs k8s_client.Clientset
	hive := hive.New(cell.Module("test", "test",
		daemon_k8s.LocalNodeCell,
		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane:             true,
					EnableBGPControlPlaneStatusReport: false,
				}
			},
			k8s_client.NewFakeClientset,
		),
		cell.Invoke(func(jg job.Group, ln daemon_k8s.LocalCiliumNodeResource, _cs k8s_client.Clientset) {
			cs = _cs

			// Create a LocalNode to obtain local node name
			_, err := cs.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Create a NodeConfig for this node
			_, err = cs.CiliumV2alpha1().CiliumBGPNodeConfigs().Create(
				ctx,
				&v2alpha1.CiliumBGPNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
					// Spec can be empty for this test
					Spec: v2alpha1.CiliumBGPNodeSpec{},
					// Fill with some dummy status
					Status: v2alpha1.CiliumBGPNodeStatus{
						BGPInstances: []v2alpha1.CiliumBGPNodeInstanceStatus{
							{
								Name: "foo",
							},
						},
					},
				},

				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Ensure the status is not empty at this point
			nc, err := cs.CiliumV2alpha1().CiliumBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
			require.NoError(t, err)
			require.False(t, nc.Status.DeepEqual(&v2alpha1.CiliumBGPNodeStatus{}), "Status is already empty before cleanup job")

			// Register cleanup job. This should cleanup the status of the NodeConfig above.
			r := &StatusReconciler{
				LocalNodeResource: ln,
				ClientSet:         cs,
			}
			jg.Add(job.OneShot("cleanup-status", r.cleanupStatus))
		}),
	))

	require.NoError(t, hive.Start(logger, ctx))
	t.Cleanup(func() {
		hive.Stop(logger, ctx)
	})

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		nc, err := cs.CiliumV2alpha1().CiliumBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
		if !assert.NoError(ct, err) {
			return
		}
		// The status should be cleared to empty
		assert.True(ct, nc.Status.DeepEqual(&v2alpha1.CiliumBGPNodeStatus{}), "Status is not empty")
	}, time.Second*5, time.Millisecond*100)
}
