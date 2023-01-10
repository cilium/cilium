// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Google Inc.

package speaker

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"

	"github.com/cilium/cilium/pkg/bgp/fence"
	"github.com/cilium/cilium/pkg/k8s"
)

// Op enumerates the operation an event
// demonstrates.
type Op int

const (
	Undefined Op = iota
	Add
	Update
	Delete
)

func (o Op) String() string {
	switch o {
	case Undefined:
		return "Undefined"
	case Add:
		return "Add"
	case Update:
		return "Update"
	case Delete:
		return "Delete"
	default:
		return fmt.Sprintf("Unknown(%d)", o)
	}
}

// svcEvent holds the extracted fields from a K8s service event
// which are of interest to the BGP package.
type svcEvent struct {
	fence.Meta
	op  Op
	id  k8s.ServiceID
	svc *metallbspr.Service
	eps *metallbspr.Endpoints
}

// epEvent is similar to svcEvent but signifies the service was
// discovered via a K8s Endpoint event.
type epEvent svcEvent

// nodeEvent holds the extracted fields from a K8s node event which are
// of interested to the BGP package.
//
// nodeEvents trigger a call to speaker.SetNodeLabels which ultimately
// syncs Cilium's BGP peer connections.
//
// this package assumes when Cilium Agent starts an initial node event
// is emitted and thus the BGP connections are setup.
type nodeEvent struct {
	fence.Meta
	op Op
	// The following fields must be a pointers because they are not hashable
	// (read comparable) in Go.

	// labels is a pointer to a copy of the incoming node event's
	// labels.
	labels *map[string]string
	// podCIDRs is the extracted pod cidr ranges associated
	// with this node event.
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
func (s *MetalLBSpeaker) run(ctx context.Context) {
	l := log.WithFields(
		logrus.Fields{
			"component": "MetalLBSpeaker.run",
		},
	)
	for {
		// only check ctx here, we'll allow any in-flight
		// events to be processed completely.
		if ctx.Err() != nil {
			return
		}
		// previous to this iteration, we processed an event
		// which indicates the speaker should yield. shut
		// it down.
		if s.shutdown > 0 { // atomic load not necessary, we are the only writer.
			l.Info("speaker shutting down.")
			return
		}
		key, quit := s.queue.Get()
		if quit {
			return
		}
		l.Info("processing new event.")
		st := s.do(key)
		switch st {
		case types.SyncStateError:
			s.queue.Add(key)
			// done must be called to requeue event after add.
		case types.SyncStateSuccess, types.SyncStateReprocessAll:
			// SyncStateReprocessAll is returned in MetalLB when the
			// configuration changes. However, we are not watching for
			// configuration changes because our configuration is static and
			// loaded once at Cilium start time.
		}
		// if queue.Add(key) is called previous to this invocation the event
		// is requeued, else it is discarded from the queue.
		s.queue.Done(key)
	}
}

// do performs the appropriate action depending on the event type. For example,
// if it is a service event (svcEvent), then it will call into MetalLB's
// SetService() to perform BGP announcements.
func (s *MetalLBSpeaker) do(key interface{}) types.SyncState {
	l := log.WithFields(
		logrus.Fields{
			"component": "MetalLBSpeaker.do",
		},
	)
	switch k := key.(type) {
	case svcEvent:
		if s.Fence(k.Meta) {
			l.WithFields(logrus.Fields{
				"uuid":     k.Meta.UUID,
				"type":     "service",
				"revision": k.Meta.Rev,
			}).Debug("Encountered stale event, will not process")
			return types.SyncStateSuccess
		}

		l.WithField("service-id", k.id.String()).Debug("announcing load balancer from service")

		st := s.speaker.SetService(k.id.String(), k.svc, k.eps)
		if st == types.SyncStateSuccess && k.op == Delete {
			// this is a delete operation and we have succcessfully
			// processed it, delete it from our fence.
			s.Clear(k.UUID)
		}
		return st
	case epEvent:
		if s.Fence(k.Meta) {
			l.WithFields(logrus.Fields{
				"uuid":     k.Meta.UUID,
				"type":     "endpoint",
				"revision": k.Meta.Rev,
			}).Debug("Encountered stale event, will not process")
			return types.SyncStateSuccess
		}
		l.WithField("endpoint-id", k.id.String()).Debug("announcing load balancer from endpoint")

		st := s.speaker.SetService(k.id.String(), k.svc, k.eps)
		if st == types.SyncStateSuccess && k.op == Delete {
			// this is a delete operation and we have succcessfully
			// processed it, delete it from our fence.
			s.Clear(k.UUID)
		}
		return st
	case nodeEvent:
		if s.Fence(k.Meta) {
			l.WithFields(logrus.Fields{
				"uuid":     k.Meta.UUID,
				"type":     "node",
				"revision": k.Meta.Rev,
			}).Debug("Encountered stale event, will not process")
			return types.SyncStateSuccess
		}
		st := s.handleNodeEvent(k)
		return st
	default:
		l.Debugf("Encountered an unknown key type %T in BGP speaker", k)
		return types.SyncStateSuccess
	}
}

func (s *MetalLBSpeaker) handleNodeEvent(k nodeEvent) types.SyncState {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.handleNodeEvent",
			"labels":    k.labels,
			"cidrs":     k.podCIDRs,
		})
	)

	if k.withDraw {
		// this is a best effort method call, so we don't
		// care about errors. If the node is shutting down
		// all routes will be closed once the speaker's TCP conn
		// is closed anyway per the rfc.
		// see: https://datatracker.ietf.org/doc/html/rfc4271#section-6

		s.withdraw()
		l.Info("node is leaving the cluster, speaker will shutdown.")
		return types.SyncStateSuccess
	}

	l.Debug("syncing bgp sessions")
	if r := s.speaker.SetNodeLabels(*k.labels); r != types.SyncStateSuccess {
		switch r {
		case types.SyncStateReprocessAll:
			l.Errorf("MetalLB resync required, requeing event: MetalLB Sync State: %v.", r)
		case types.SyncStateError:
			l.Errorf("Speaker resync required, requeing event: MetalLB Sync State: %v.", r)
		default:
			l.Errorf("Unknown sync state returned from Speaker: %v", r)
		}
		return r
	}

	if s.announcePodCIDR {
		l.Debug("announcing pod CIDR(s)")
		if err := s.announcePodCIDRs(*k.podCIDRs); err != nil {
			l.WithError(err).WithField("CIDRs", k.podCIDRs).Error("Failed to announce pod CIDRs")
			return types.SyncStateError
		}
	}

	return types.SyncStateSuccess
}
