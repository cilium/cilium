// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/time"
)

type peerStatusReporter interface {
	Status() pool.Status
}
type healthServer struct {
	svc *health.Server
	pm  peerStatusReporter

	probeInterval time.Duration
	stopChan      chan struct{}
}

// newHealthServer creates a new health server that monitors health
// using the provided status reporter
func newHealthServer(pm peerStatusReporter, probeInterval time.Duration) *healthServer {
	svc := health.NewServer()
	svc.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	svc.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_NOT_SERVING)
	hs := &healthServer{
		svc:           svc,
		pm:            pm,
		probeInterval: probeInterval,
		stopChan:      make(chan struct{}),
	}
	return hs
}

// start starts the health server.
func (hs healthServer) start() {
	check := func() {
		st := hs.pm.Status()
		if st.PeerServiceConnected && st.AvailablePeers > 0 {
			hs.svc.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			hs.svc.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)
		} else {
			hs.svc.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
			hs.svc.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_NOT_SERVING)
		}
	}
	go func() {
		connTimer, connTimerDone := inctimer.New()
		defer connTimerDone()
		check()
		for {
			select {
			case <-hs.stopChan:
				return
			case <-connTimer.After(hs.probeInterval):
				check()
			}
		}
	}()
}

// stop stops the health server.
func (hs healthServer) stop() {
	close(hs.stopChan)
}
