// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"

	"github.com/cilium/hive/cell"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (s *Service) healthCheckCallback(_ int, data any) {
	s.healthCheckChan <- data
}

func (s *Service) handleHealthCheckEvent(ctx context.Context, health cell.Health) error {
	health.OK("Waiting for health check events")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case data := <-s.healthCheckChan:
			switch d := data.(type) {
			case HealthCheckCBBackendEventData:
				svcAddr := d.SvcAddr
				beAddr := d.BeAddr
				beState := d.BeState
				s.logger.Debug(
					"Health check backend update",
					logfields.Service, svcAddr,
					logfields.Backend, beAddr,
					logfields.BackendState, beState,
				)
				be := lb.NewBackendWithState(0, beAddr.Protocol, beAddr.AddrCluster, beAddr.Port, 0, beState)

				var (
					svcs []lb.L3n4Addr
					err  error
				)
				if svcs, err = s.UpdateBackendStateServiceOnly(svcAddr, be); err != nil {
					health.Degraded("Error updating backend state", err)
					continue
				}

				for _, svc := range svcs {
					s.logger.Debug(
						"Notify health update subscribers for service",
						logfields.Service, svc,
					)
					s.notifyHealthCheckUpdateSubscribers(svc)
				}
			case HealthCheckCBSvcEventData:
				s.logger.Debug(
					"Health check service update",
					logfields.Service, d.SvcAddr,
				)
				svcAddr := d.SvcAddr
				s.notifyHealthCheckUpdateSubscribers(svcAddr)
			}
		}
	}
}

func (s *Service) Subscribe(ctx context.Context, updateCB HealthUpdateCallback) {
	s.Lock()
	defer s.Unlock()

	// Replay the current state to let the subscriber to catch up
	for _, svc := range s.svcByHash {
		if svc == nil {
			continue
		}
		updateCB(s.healthUpdateFromSvcInfo(svc))
	}

	s.healthCheckSubscribers = append(s.healthCheckSubscribers, HealthSubscriber{
		Ctx:      ctx,
		Callback: updateCB,
	})
}

func (s *Service) notifyHealthCheckUpdateSubscribers(svcAddr lb.L3n4Addr) {
	s.RLock()
	defer s.RUnlock()
	if len(s.healthCheckSubscribers) == 0 {
		return
	}
	info, found := s.svcByHash[svcAddr.Hash()]
	if !found {
		// Service not found in case it was deleted.
		return
	}
	for _, subscriber := range s.healthCheckSubscribers {
		if subscriber.Ctx.Err() == nil {
			subscriber.Callback(s.healthUpdateFromSvcInfo(info))
		}
	}
}

func (s *Service) notifyHealthCheckUpdateSubscribersServiceDelete(svc *svcInfo) {
	s.logger.Debug("Notify health update subscribers about deleted service (0 active backends)", logfields.Service, svc.svcName)
	svc.backends = []*lb.LegacyBackend{} // reset backends
	for _, subscriber := range s.healthCheckSubscribers {
		if subscriber.Ctx.Err() == nil {
			subscriber.Callback(s.healthUpdateFromSvcInfo(svc))
		}
	}
}

func (s *Service) healthUpdateFromSvcInfo(info *svcInfo) HealthUpdateSvcInfo {
	activeBes := make([]lb.LegacyBackend, 0, len(info.backends))
	for _, backend := range info.backends {
		if backend == nil {
			// https://github.com/cilium/cilium/pull/23446
			continue
		}
		if backend.State == lb.BackendStateActive {
			activeBes = append(activeBes, *backend)
		}
	}
	return HealthUpdateSvcInfo{
		Name:           info.svcName,
		Addr:           info.frontend.L3n4Addr,
		SvcType:        info.svcType,
		ActiveBackends: activeBes,
	}
}
