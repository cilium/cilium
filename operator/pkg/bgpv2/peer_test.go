// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type peerConfigTestFixture struct {
	hive               *hive.Hive
	fakeClientSet      *k8s_client.FakeClientset
	peerConfigResource resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]

	db          *statedb.DB
	healthTable statedb.Table[healthTypes.Status]
}

func newPeerConfigTestFixture(t *testing.T, ctx context.Context, enableStatusReport bool) (*peerConfigTestFixture, func()) {
	f := &peerConfigTestFixture{}

	type watchSync struct {
		once    sync.Once
		watchCh chan any
	}

	rws := map[string]*watchSync{
		"ciliumbgppeerconfigs": {watchCh: make(chan any)},
	}

	if enableStatusReport {
		rws["secrets"] = &watchSync{watchCh: make(chan any)}
	}

	reactorFn := func(tracker k8sTesting.ObjectTracker) func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		return func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
			w := action.(k8sTesting.WatchAction)
			gvr := w.GetResource()
			ns := w.GetNamespace()
			watch, err := tracker.Watch(gvr, ns)
			if err != nil {
				return false, nil, err
			}
			rw, ok := rws[w.GetResource().Resource]
			if !ok {
				return false, watch, nil
			}
			rw.once.Do(func() { close(rw.watchCh) })
			return true, watch, nil
		}
	}

	// make sure watchers are initialized before the test starts
	watchersReadyFn := func() {
		for name, rw := range rws {
			select {
			case <-ctx.Done():
				require.Fail(t, fmt.Sprintf("Context expired while waiting for %s", name))
			case <-rw.watchCh:
			}
		}
	}

	hive := hive.New(
		cell.Module("test", "test",
			cell.Provide(
				k8s_client.NewFakeClientset,
				newSecretResource,
				k8s.CiliumBGPPeerConfigResource,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableBGPControlPlane:             true,
						BGPSecretsNamespace:               "kube-system",
						EnableBGPControlPlaneStatusReport: enableStatusReport,
					}
				},
			),
			cell.Invoke(
				registerPeerConfigStatusReconciler,
				func(
					fcs *k8s_client.FakeClientset,
					p resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig],
					db *statedb.DB,
					h statedb.Table[healthTypes.Status],
				) {
					f.fakeClientSet = fcs
					f.peerConfigResource = p
					f.db = db
					f.healthTable = h
					f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor(
						"*",
						reactorFn(f.fakeClientSet.CiliumFakeClientset.Tracker()),
					)
					f.fakeClientSet.SlimFakeClientset.PrependWatchReactor(
						"*",
						reactorFn(f.fakeClientSet.SlimFakeClientset.Tracker()),
					)
				},
			),
		),
	)
	f.hive = hive

	return f, watchersReadyFn
}

func TestMissingAuthSecretCondition(t *testing.T) {
	secretName := "auth-secret"
	secretNamespace := "kube-system"
	peerConfigName := "peer-config0"

	secret := &slim_core_v1.Secret{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
	}

	tests := []struct {
		name          string
		peerConfig    *cilium_api_v2alpha1.CiliumBGPPeerConfig
		expectedState meta_v1.ConditionStatus
	}{
		{
			name: "MissingAuthSecret False",
			peerConfig: &cilium_api_v2alpha1.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
					AuthSecretRef: ptr.To(secretName),
				},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret False nil AuthSecretRef",
			peerConfig: &cilium_api_v2alpha1.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret True",
			peerConfig: &cilium_api_v2alpha1.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
					AuthSecretRef: ptr.To(secretName + "foo"),
				},
			},
			expectedState: meta_v1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f, ready := newPeerConfigTestFixture(t, ctx, true)

			f.hive.Start(slog.Default(), ctx)
			t.Cleanup(func() {
				f.hive.Stop(slog.Default(), ctx)
			})

			ready()

			_, err := f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPPeerConfigs().Create(
				ctx, tt.peerConfig, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			_, err = f.fakeClientSet.SlimFakeClientset.CoreV1().Secrets(secretNamespace).Create(
				ctx, secret, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			peerConfigStore, err := f.peerConfigResource.Store(ctx)
			require.NoError(t, err)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				pc, exists, err := peerConfigStore.GetByKey(resource.Key{
					Name: peerConfigName,
				})
				if !assert.NoError(ct, err, "Failed to get peer config") {
					return
				}
				if !assert.True(ct, exists, "Peer config not found") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					cilium_api_v2alpha1.BGPPeerConfigConditionMissingAuthSecret,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisablePeerConfigStatusReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	f, ready := newPeerConfigTestFixture(t, ctx, false)

	logger := hivetest.Logger(t)

	f.hive.Start(logger, ctx)
	t.Cleanup(func() {
		f.hive.Stop(logger, ctx)
	})

	ready()

	peerConfig := &cilium_api_v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPPeerConfigSpec{
			AuthSecretRef: ptr.To("secret0"),
		},
		Status: cilium_api_v2alpha1.CiliumBGPPeerConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range cilium_api_v2alpha1.AllBGPPeerConfigConditions {
		peerConfig.Status.Conditions = append(peerConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}

	_, err := f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPPeerConfigs().Create(
		ctx, peerConfig, meta_v1.CreateOptions{},
	)
	require.NoError(t, err)

	peerConfigStore, err := f.peerConfigResource.Store(ctx)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		pc, exists, err := peerConfigStore.GetByKey(resource.Key{
			Name: peerConfig.Name,
		})
		if !assert.NoError(ct, err, "Failed to get peer config") {
			return
		}
		if !assert.True(ct, exists, "Peer config not found") {
			return
		}
		assert.Empty(ct, pc.Status.Conditions, "Conditions are not cleared")

		rtxn := f.db.ReadTxn()

		o, _, found := f.healthTable.Get(rtxn, health.PrimaryIndex.Query(healthTypes.HealthID("test.job-cleanup-peer-config-status")))
		if !assert.True(ct, found, "Health status for the job is not found") {
			return
		}

		assert.Equal(ct, healthTypes.Level(healthTypes.LevelOK), o.Level)
		assert.Equal(ct, "Cleanup job is done successfully", o.Message)
	}, time.Second*3, time.Millisecond*100)
}
