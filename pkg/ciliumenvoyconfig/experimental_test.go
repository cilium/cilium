// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
)

func TestCECController(t *testing.T) {
	lbFiles := []string{
		"testdata/experimental/service.yaml",
		"testdata/experimental/service2.yaml",
		"testdata/experimental/endpointslice.yaml",
		"testdata/experimental/endpointslice2.yaml",
	}

	cecLW, ccecLW := testutils.NewFakeListerWatcher(), testutils.NewFakeListerWatcher()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	fakeEnvoy := &fakeEnvoySyncer{}
	fakeTrigger := &fakePolicyTrigger{}

	var (
		db     *statedb.DB
		writer *experimental.Writer
	)

	hive := hive.New(
		experimental.TestCell,
		experimental.TestInputsFromFiles(t, lbFiles),

		cell.Module("cec-test", "test",
			// cecResourceParser and its friends.
			cell.Group(
				cell.Provide(
					newCECResourceParser,
					func() PortAllocator { return NewMockPortAllocator() },
				),
				node.LocalNodeStoreCell,
			),

			experimentalTableCells,
			experimentalControllerCells,

			cell.ProvidePrivate(
				func() listerWatchers {
					return listerWatchers{
						cec:  cecLW,
						ccec: ccecLW,
					}
				},
				func() promise.Promise[synced.CRDSync] {
					return promise.Resolved(synced.CRDSync{})
				},
				func() envoySyncer { return fakeEnvoy },
				func() policyTrigger { return fakeTrigger },
			),

			cell.Invoke(
				func(db_ *statedb.DB, w *experimental.Writer) {
					db = db_
					writer = w
				},
			),
		),
	)

	require.NoError(t, hive.Start(log, context.TODO()), "Start")

	require.NoError(
		t,
		cecLW.UpsertFromFile("testdata/experimental/ciliumenvoyconfig.yaml"),
		"Upsert ciliumenvoyconfig.yaml",
	)
	require.NoError(
		t,
		ccecLW.UpsertFromFile("testdata/experimental/ciliumclusterwideenvoyconfig.yaml"),
		"Upsert ciliumclusterwideenvoyconfig.yaml",
	)

	ok := assert.Eventually(
		t,
		func() bool {
			txn := db.ReadTxn()

			svc, _, found := writer.Services().Get(
				txn,
				experimental.ServiceByName(loadbalancer.ServiceName{Namespace: "test", Name: "echo"}),
			)
			if !found || svc.ProxyRedirect == nil {
				t.Logf("test/echo not found or not redirected.")
				return false
			}

			svc, _, found = writer.Services().Get(
				txn,
				experimental.ServiceByName(loadbalancer.ServiceName{Namespace: "test", Name: "echo2"}),
			)
			if !found || svc.ProxyRedirect == nil {
				t.Logf("test/echo2 not found or not redirected.")
				return false
			}

			if fakeEnvoy.lastUpdate.Load() == nil || fakeEnvoy.lastUpsert.Load() == nil {
				t.Logf("envoy updates not done yet.")
				return false
			}

			if fakeTrigger.count.Load() < 1 {
				t.Logf("policy trigger not done yet.")
				return false
			}

			return true
		},
		time.Second,
		50*time.Millisecond,
	)
	if !ok {
		var w strings.Builder
		writer.DebugDump(db.ReadTxn(), &w)
		t.Log("Tables:\n", w.String())
	}

	require.NoError(t, hive.Stop(log, context.TODO()), "Stop")
}

type fakeEnvoySyncer struct {
	lastUpdate atomic.Pointer[envoy.Resources]
	lastDelete atomic.Pointer[envoy.Resources]
	lastUpsert atomic.Pointer[envoy.Resources]
}

// DeleteResources implements envoySyncer.
func (f *fakeEnvoySyncer) DeleteResources(ctx context.Context, res envoy.Resources) {
	f.lastDelete.Store(&res)
}

// UpdateResources implements envoySyncer.
func (f *fakeEnvoySyncer) UpdateResources(ctx context.Context, old envoy.Resources, new envoy.Resources) {
	f.lastUpdate.Store(&new)
}

// UpsertResources implements envoySyncer.
func (f *fakeEnvoySyncer) UpsertResources(ctx context.Context, res envoy.Resources) {
	f.lastUpsert.Store(&res)
}

var _ envoySyncer = &fakeEnvoySyncer{}

type fakePolicyTrigger struct {
	count atomic.Int32
}

// TriggerPolicyUpdates implements policyTrigger.
func (f *fakePolicyTrigger) TriggerPolicyUpdates() {
	f.count.Add(1)
}

var _ policyTrigger = &fakePolicyTrigger{}
