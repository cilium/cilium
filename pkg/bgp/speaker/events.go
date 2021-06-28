// Copyright 2017 Google Inc.
// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package speaker

import (
	"context"
	"sync/atomic"

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
type nodeEvent struct {
	// The following fields must be a pointers because they are not hashable
	// (read comparable) in Go.
	labels   *map[string]string
	podCIDRs *[]string
	// withDraw will be set when a Delete node event occurs.
	// the reduction of this event will elicit a withdrawal
	// of all bgp routes.
	withDraw bool
}

// run runs the reconciliation loop, fetching events off of the queue to
// process. The events supported are svcEvent, epEvent, and nodeEvent. This
// loop is only stopped (implicitly) when the Agent is shutting down.
//
// Adapted from go.universe.tf/metallb/pkg/k8s/k8s.go.
func (s *Speaker) run(ctx context.Context) {
	for {
		// only check ctx here, we'll allow any in-flight
		// events to be processed completely.
		if ctx.Err() != nil {
			return
		}
		// previous to this iteration, we processed an event
		// which indicates the speaker should yield. shut
		// it down.
		if s.shutdown > 0 {
			return
		}
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
		return s.handleNodeEvent(k)
	default:
		log.Debugf("Encountered an unknown key type %T in BGP speaker", k)
		return types.SyncStateSuccess
	}
}

func (s *Speaker) handleNodeEvent(k nodeEvent) types.SyncState {
	var (
		ret    types.SyncState
		failed bool
	)

	if k.withDraw {
		// this is a best effort method call, so we don't
		// care about errors. If the node is shutting down
		// all routes will be closed once the speaker's TCP conn
		// is closed anyway per the rfc.
		// see: https://datatracker.ietf.org/doc/html/rfc4271#section-6
		s.withDraw()
		atomic.AddInt32(&s.shutdown, 1)
		return types.SyncStateSuccess
	}

	if s.announceLBIP {
		if r := s.SetNodeLabels(s.logger, *k.labels); r != types.SyncStateSuccess {
			failed = true
			ret = r
		}
	}
	if s.announcePodCIDR {
		if err := s.announcePodCIDRs(*k.podCIDRs); err != nil {
			if !failed {
				failed = true
				ret = types.SyncStateError
			}
			log.WithError(err).WithField("CIDRs", k.podCIDRs).Error("Failed to announce pod CIDRs")
		}
	}

	if failed {
		return ret
	}
	return types.SyncStateSuccess
}
