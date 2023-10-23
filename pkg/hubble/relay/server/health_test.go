// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"
	"github.com/cilium/cilium/pkg/lock"
)

func TestHealthServer(t *testing.T) {

	fpr := &fakePeerStatusReporter{}
	hs := newHealthServer(fpr, 10*time.Millisecond)

	hs.start()
	t.Run("initially unavailable", func(t *testing.T) {
		eventuallServingStatus(t, hs.svc, healthpb.HealthCheckResponse_NOT_SERVING)
	})
	t.Run("updated available", func(t *testing.T) {
		fpr.setStatus(pool.Status{
			PeerServiceConnected: true,
			AvailablePeers:       3,
		})
		eventuallServingStatus(t, hs.svc, healthpb.HealthCheckResponse_SERVING)
	})
	t.Run("updated if no available peers", func(t *testing.T) {
		fpr.setStatus(pool.Status{
			PeerServiceConnected: true,
			AvailablePeers:       0,
		})
		eventuallServingStatus(t, hs.svc, healthpb.HealthCheckResponse_NOT_SERVING)
	})
	t.Run("updated if peers back", func(t *testing.T) {
		fpr.setStatus(pool.Status{
			PeerServiceConnected: true,
			AvailablePeers:       6,
		})
		eventuallServingStatus(t, hs.svc, healthpb.HealthCheckResponse_SERVING)
	})
	t.Run("updated if peer service unavailable", func(t *testing.T) {
		fpr.setStatus(pool.Status{
			PeerServiceConnected: false,
			AvailablePeers:       6,
		})
		eventuallServingStatus(t, hs.svc, healthpb.HealthCheckResponse_NOT_SERVING)
	})
	hs.stop()
}

func eventuallServingStatus(t *testing.T, svc healthpb.HealthServer, status healthpb.HealthCheckResponse_ServingStatus) {
	t.Helper()
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := svc.Check(context.TODO(), &healthpb.HealthCheckRequest{
			Service: "",
		})
		assert.NoError(c, err)
		assert.Equal(c, status, res.Status)

		res, err = svc.Check(context.TODO(), &healthpb.HealthCheckRequest{
			Service: v1.ObserverServiceName,
		})
		assert.NoError(c, err)
		assert.Equal(c, status, res.Status)
	}, 5*time.Second, 10*time.Millisecond)
}

type fakePeerStatusReporter struct {
	mu lock.Mutex

	status pool.Status
}

func (f *fakePeerStatusReporter) setStatus(stat pool.Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = stat
}

// Status implements peerStatusReporter.
func (f *fakePeerStatusReporter) Status() pool.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}
