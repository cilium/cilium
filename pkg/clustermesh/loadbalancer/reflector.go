// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/loadbalancer"
	reflectorEndpoints "github.com/cilium/cilium/pkg/loadbalancer/reflectors/endpoints"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const reflectorBufferSize = 500

type reflectorParams struct {
	cell.In

	Log        *slog.Logger
	JobGroup   job.Group
	Writer     *writer.Writer
	Config     loadbalancer.Config
	ExtConfig  loadbalancer.ExternalConfig
	TestConfig *loadbalancer.TestConfig `optional:"true"`
	cmtypes.ServiceModeV2Config
}

func (p reflectorParams) waitTime() time.Duration {
	if p.TestConfig != nil {
		// Use a much lower wait time in tests to trigger more edge cases and make them faster.
		return 10 * time.Millisecond
	}
	return p.Config.ReflectorWaitTime
}

func registerEndpointSliceReflector(p reflectorParams, observer *endpointSliceObserver) {
	if observer == nil {
		return
	}

	initComplete := p.Writer.RegisterInitializer("clustermesh")
	p.JobGroup.Add(
		job.OneShot("reflect-endpointslices", func(ctx context.Context, health cell.Health) error {
			return runEndpointSliceReflector(ctx, p, observer, initComplete)
		}),
	)
}

func runEndpointSliceReflector(ctx context.Context, p reflectorParams, observer *endpointSliceObserver, initComplete func(writer.WriteTxn)) error {
	currentEndpointsByCluster := map[uint32]reflectorEndpoints.Cache{}

	processEndpointsEvent := func(txn writer.WriteTxn, key bufferKey, val bufferValue) error {
		if val.synced {
			initComplete(txn)
			return nil
		}

		allEps := val.allEndpoints
		currentEndpoints := currentEndpointsByCluster[key.clusterID]
		if currentEndpoints == nil {
			currentEndpoints = reflectorEndpoints.Cache{}
			currentEndpointsByCluster[key.clusterID] = currentEndpoints
		}

		// Convert [k8s.Endpoints] to [loadbalancer.Backend]
		backends := reflectorEndpoints.Convert(p.Log, p.ExtConfig, key.serviceName, allEps.Backends())

		if err := p.Writer.UpsertAndReleaseBackends(txn, key.serviceName, source.ClusterMesh, key.clusterID, backends, currentEndpoints.Orphans(allEps.All())); err != nil {
			return err
		}

		currentEndpoints.UpdateMany(allEps.All())
		if len(currentEndpoints) == 0 {
			delete(currentEndpointsByCluster, key.clusterID)
		}

		return nil
	}

	bufferPool := sync.Pool{
		New: func() any {
			return container.NewInsertOrderedMap[bufferKey, bufferValue]()
		},
	}

	events := stream.ToChannel(
		ctx,
		stream.Buffer(
			observer,
			reflectorBufferSize,
			p.waitTime(),
			func(buf buffer, ev endpointSliceEvent) buffer {
				if buf == nil {
					buf = bufferPool.Get().(buffer)
				}
				return bufferInsert(buf, ev)
			},
		),
	)

	for buf := range events {
		txn := p.Writer.WriteTxn()
		for key, val := range buf.All() {
			if err := processEndpointsEvent(txn, key, val); err != nil {
				txn.Abort()
				return err
			}
		}
		txn.Commit()
		buf.Clear()
		bufferPool.Put(buf)
	}

	return nil
}

type bufferKey struct {
	serviceName loadbalancer.ServiceName
	clusterID   uint32
}

type bufferValue struct {
	synced       bool
	allEndpoints reflectorEndpoints.AllEndpoints
}

// buffer for holding a batch of endpoints event
type buffer = *container.InsertOrderedMap[bufferKey, bufferValue]

func bufferInsert(buf buffer, ev endpointSliceEvent) buffer {
	switch ev.kind {
	case resource.Upsert, resource.Delete:
		key := bufferKey{
			ev.obj.ServiceName,
			ev.clusterID,
		}
		var allEps reflectorEndpoints.AllEndpoints
		if old, ok := buf.Get(key); ok {
			allEps = old.allEndpoints
		}
		// Since we may merge a mixture of Upsert and Delete events together we handle
		// deletion as an Upsert of [endpoints.Endpoints] with nil backends.
		allEps = allEps.Insert(ev.kind == resource.Delete, ev.obj)
		buf.Insert(key, bufferValue{
			synced:       false,
			allEndpoints: allEps,
		})
	case resource.Sync:
		buf.Insert(bufferKey{}, bufferValue{synced: true})
	default:
		panic("unexpected clustermesh loadbalancer.endpointSliceEvent")
	}
	return buf
}
