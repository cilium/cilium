// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmendpointslice "github.com/cilium/cilium/pkg/clustermesh/endpointslice"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
)

type EndpointSlicesSyncedFunc func(context.Context) error

type endpointSliceEvent struct {
	kind      resource.EventKind
	obj       *k8s.Endpoints
	clusterID uint32
}

type endpointSliceObserver struct {
	log *slog.Logger

	buf    []endpointSliceEvent
	mu     lock.Mutex
	emitFn func(endpointSliceEvent)

	started atomic.Bool
}

type observerParams struct {
	cell.In

	Log    *slog.Logger
	Writer *writer.Writer

	ClusterInfo cmtypes.ClusterInfo
	common.Config
	cmtypes.ServiceModeV2Config
}

func newEndpointSliceObserver(p observerParams) (cmendpointslice.Observer, *endpointSliceObserver) {
	if !p.Writer.IsEnabled() || !p.ServiceModeV2.ShouldWatchEndpointSlices() || p.ClusterInfo.ID == 0 || p.ClusterMeshConfig == "" {
		return nil, nil
	}

	observer := &endpointSliceObserver{log: p.Log}
	observer.emitFn = func(ev endpointSliceEvent) {
		observer.buf = append(observer.buf, ev)
	}

	return observer, observer
}

func (o *endpointSliceObserver) registerEndpointSliceSynced(jg job.Group, synced EndpointSlicesSyncedFunc) {
	if synced == nil || o == nil {
		return
	}
	jg.Add(job.OneShot("synced-endpointslices", func(ctx context.Context, health cell.Health) error {
		if err := synced(ctx); err != nil {
			return err
		}
		o.emit(endpointSliceEvent{kind: resource.Sync})
		return nil
	}))
}

func (o *endpointSliceObserver) emit(ev endpointSliceEvent) {
	// [stream.Observable] is the interface that we implement in this struct
	// and it must not send any concurrent event. The lock below helps to hold
	// that guarantee in addition to handle a mutation of emitFn when the
	// observer is initialized.
	o.mu.Lock()
	defer o.mu.Unlock()

	o.emitFn(ev)
}

func (o *endpointSliceObserver) OnUpdate(k store.Key) {
	eps, ok := k.(*endpointslicetypes.ValidatingClusterEndpointSlice)
	if !ok {
		return
	}
	o.emit(endpointSliceEvent{
		kind:      resource.Upsert,
		obj:       k8s.ParseEndpointSliceV1(o.log, eps.ClusterEndpointSlice.ToShallowSlimEndpointSlice()),
		clusterID: eps.ClusterID,
	})
}

func (o *endpointSliceObserver) OnDelete(k store.NamedKey) {
	eps, ok := k.(*endpointslicetypes.ValidatingClusterEndpointSlice)
	if !ok {
		return
	}
	o.emit(endpointSliceEvent{
		kind:      resource.Delete,
		obj:       k8s.ParseEndpointSliceV1(o.log, eps.ClusterEndpointSlice.ToShallowSlimEndpointSlice()),
		clusterID: eps.ClusterID,
	})
}

func (o *endpointSliceObserver) Observe(ctx context.Context, next func(endpointSliceEvent), complete func(error)) {
	if o.started.Swap(true) {
		panic("BUG: calling [endpointSliceObserver.Observe] multiple times is not supported")
	}

	go func() {
		defer func() {
			o.mu.Lock()
			o.emitFn = func(endpointSliceEvent) {}
			o.mu.Unlock()

			complete(ctx.Err())
		}()

		o.mu.Lock()
		for _, el := range o.buf {
			select {
			case <-ctx.Done():
				o.mu.Unlock()
				return

			default:
				next(el)
			}
		}

		o.buf = nil
		o.emitFn = next
		o.mu.Unlock()

		<-ctx.Done()
	}()
}
