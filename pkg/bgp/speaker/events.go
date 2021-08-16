// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium
// Copyright 2017 Google Inc.

package speaker

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/sirupsen/logrus"

	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
)

// svcEvent holds the extracted fields from a K8s service event
// which are of interest to the BGP package.
type svcEvent struct {
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
			s.queue.Done(key)
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
func (s *MetalLBSpeaker) do(key interface{}) types.SyncState {
	defer s.queue.Done(key)
	l := log.WithFields(
		logrus.Fields{
			"component": "MetalLBSpeaker.do",
		},
	)
	switch k := key.(type) {
	case svcEvent:
		l.WithField("service-id", k.id.String()).Debug("announcing load balancer from service")
		return s.speaker.SetService(k.id.String(), k.svc, k.eps)
	case epEvent:
		l.WithField("endpoint-id", k.id.String()).Debug("announcing load balancer from endpoint")
		return s.speaker.SetService(k.id.String(), k.svc, k.eps)
	case nodeEvent:
		return s.handleNodeEvent(k)
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
