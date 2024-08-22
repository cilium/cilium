// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"

	"github.com/sirupsen/logrus"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

func (s *Service) HealthCheckCallback(event int, data any) {
	switch event {
	case HealthCheckCBBackendEvent:
		if d, ok := data.(HealthCheckCBBackendEventData); ok {
			svcAddr := d.SvcAddr
			beAddr := d.BeAddr
			beState := d.BeState
			log.WithFields(logrus.Fields{
				"svc_addr": svcAddr,
				"be":       beAddr,
				"state":    beState,
			}).Info("Health check backend update")
			be := lb.NewBackendWithState(0, beAddr.Protocol, beAddr.AddrCluster, beAddr.Port, 0, beState)

			var (
				svcs []lb.L3n4Addr
				err  error
			)
			if svcs, err = s.UpdateBackendStateServiceOnly(svcAddr, be); err != nil {
				log.Errorf("health check cb: error updating backend state: %v", err)
				return
			}

			for _, svc := range svcs {
				log.Infof("Notify health update subscribers for service %v", svc)
				s.notifyHealthCheckUpdateSubscribers(svc)
			}
		}
	case HealthCheckCBSvcEvent:
		if d, ok := data.(HealthCheckCBSvcEventData); ok {
			log.WithFields(logrus.Fields{
				"svc_addr": d.SvcAddr,
			}).Info("Health check service update")
			svcAddr := d.SvcAddr
			s.notifyHealthCheckUpdateSubscribers(svcAddr)
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

func (s *Service) healthUpdateFromSvcInfo(info *svcInfo) HealthUpdateSvcInfo {
	activeBes := make([]lb.Backend, 0, len(info.backends))
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
