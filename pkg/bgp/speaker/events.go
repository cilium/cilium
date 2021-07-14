// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium
// Copyright 2017 Google Inc.

package speaker

import (
	"github.com/cilium/cilium/pkg/k8s"

	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
)

type svcEvent struct {
	id  k8s.ServiceID
	svc *metallbspr.Service
	eps *metallbspr.Endpoints
}
type epEvent svcEvent

// nodeEvent must be a pointer to a map because maps are not hashable, aka
// cannot be keys in a map, which queue is.
type nodeEvent *map[string]string

// run runs the reconciliation loop, fetching events off of the queue to
// process. The events supported are svcEvent, epEvent, and nodeEvent. This
// loop is only stopped (implicitly) when the Agent is shutting down.
//
// Adapted from go.universe.tf/metallb/pkg/k8s/k8s.go.
func (s *Speaker) run() {
	for {
		key, quit := s.queue.Get()
		if quit {
			return
		}
		st := s.do(key)
		switch st {
		case types.SyncStateError:
			s.queue.Add(key)
		case types.SyncStateSuccess, types.SyncStateReprocessAll:
			// SyncStateReprocessAll is returned in MetalLB when the
			// configuration changes. However, we are not watching for
			// configuration changes because our configuration is static and
			// loaded once at Cilium start time.
		}
	}
}

// do performs the appropriate action depending on the event type. For example,
// if it is a service event (svcEvent), then it will call into MetalLB's
// SetService() to perform BGP announcements.
func (s *Speaker) do(key interface{}) types.SyncState {
	defer s.queue.Done(key)

	switch k := key.(type) {
	case svcEvent:
		return s.SetService(s.logger, k.id.String(), k.svc, k.eps)
	case epEvent:
		return s.SetService(s.logger, k.id.String(), k.svc, k.eps)
	case nodeEvent:
		return s.SetNodeLabels(s.logger, *k)
	default:
		log.Debugf("Encountered an unknown key type %T in BGP speaker", k)
		return types.SyncStateSuccess
	}
}
