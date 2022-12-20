// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// EndpointRegenerationEvent contains all fields necessary to regenerate an endpoint.
type EndpointRegenerationEvent struct {
	regenContext *regenerationContext
	ep           *Endpoint
}

// Handle handles the regeneration event for the endpoint.
func (ev *EndpointRegenerationEvent) Handle(res chan interface{}) {
	e := ev.ep
	regenContext := ev.regenContext

	err := e.rlockAlive()
	if err != nil {
		e.logDisconnectedMutexAction(err, "before regeneration")
		res <- &EndpointRegenerationResult{
			err: err,
		}

		return
	}
	e.runlock()

	// We should only queue the request after we use all the endpoint's
	// lock/unlock. Otherwise this can get a deadlock if the endpoint is
	// being deleted at the same time. More info PR-1777.
	doneFunc, err := e.owner.QueueEndpointBuild(regenContext.parentContext, uint64(e.ID))
	if err != nil {
		e.getLogger().WithError(err).Warning("unable to queue endpoint build")
	} else if doneFunc != nil {
		e.getLogger().Debug("Dequeued endpoint from build queue")

		regenContext.DoneFunc = doneFunc

		err = ev.ep.regenerate(ev.regenContext)

		doneFunc()
		e.notifyEndpointRegeneration(err)
	} else {
		// If another build has been queued for the endpoint, that means that
		// that build will be able to take care of all of the work needed to
		// regenerate the endpoint at this current point in time; queueing
		// another build is a waste of resources.
		e.getLogger().Debug("build not queued for endpoint because another build has already been queued")
	}

	res <- &EndpointRegenerationResult{
		err: err,
	}
	return
}

// EndpointRegenerationResult contains the results of an endpoint regeneration.
type EndpointRegenerationResult struct {
	err error
}

// EndpointRevisionBumpEvent contains all fields necessary to bump the policy
// revision of a given endpoint.
type EndpointRevisionBumpEvent struct {
	Rev uint64
	ep  *Endpoint
}

// Handle handles the revision bump event for the Endpoint.
func (ev *EndpointRevisionBumpEvent) Handle(res chan interface{}) {
	// TODO: if the endpoint is not in a 'ready' state that means that
	// we cannot set the policy revision, as something else has
	// changed endpoint state which necessitates regeneration,
	// *or* the endpoint is in a not-ready state (i.e., a prior
	// regeneration failed, so there is no way that we can
	// realize the policy revision yet. Should this be signaled
	// to the routine waiting for the result of this event?
	ev.ep.SetPolicyRevision(ev.Rev)
	res <- struct{}{}
}

// PolicyRevisionBumpEvent queues an event for the given endpoint to set its
// realized policy revision to rev. This may block depending on if events have
// been queued up for the given endpoint. It blocks until the event has
// succeeded, or if the event has been cancelled.
func (e *Endpoint) PolicyRevisionBumpEvent(rev uint64) {
	epBumpEvent := eventqueue.NewEvent(&EndpointRevisionBumpEvent{Rev: rev, ep: e})
	// Don't check policy revision event results - it is best effort.
	_, err := e.eventQueue.Enqueue(epBumpEvent)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.PolicyRevision: rev,
			logfields.EndpointID:     e.ID,
		}).Errorf("enqueue of EndpointRevisionBumpEvent failed: %s", err)
	}
}

// EndpointNoTrackEvent contains all fields necessary to update the NOTRACK rules.
type EndpointNoTrackEvent struct {
	ep     *Endpoint
	annoCB AnnotationsResolverCB
}

// Handle handles the NOTRACK rule update.
func (ev *EndpointNoTrackEvent) Handle(res chan interface{}) {
	var port uint16

	e := ev.ep

	// If this endpoint is going away, nothing to do.
	if err := e.lockAlive(); err != nil {
		res <- &EndpointRegenerationResult{
			err: nil,
		}
		return
	}

	defer e.unlock()

	portStr, err := ev.annoCB(e.K8sNamespace, e.K8sPodName)
	if err != nil {
		res <- &EndpointRegenerationResult{
			err: err,
		}
		return
	}

	if portStr == "" {
		port = 0
	} else {
		// Validate annotation before we do any actual alteration to the endpoint.
		p64, err := strconv.ParseUint(portStr, 10, 16)
		// Port should be within [1-65535].
		if err != nil || p64 == 0 {
			res <- &EndpointRegenerationResult{
				err: err,
			}
			return
		}
		port = uint16(p64)
	}

	if port != e.noTrackPort {
		log.Debug("Updating NOTRACK rules")
		if e.IPv4.IsValid() {
			if port > 0 {
				err = e.owner.Datapath().InstallNoTrackRules(e.IPv4.String(), port, false)
				log.WithError(err).Warn("Error installing iptable NOTRACK rules")
			}
			if e.noTrackPort > 0 {
				err = e.owner.Datapath().RemoveNoTrackRules(e.IPv4.String(), e.noTrackPort, false)
				log.WithError(err).Warn("Error removing iptable NOTRACK rules")
			}
		}
		if e.IPv6.IsValid() {
			if port > 0 {
				e.owner.Datapath().InstallNoTrackRules(e.IPv6.String(), port, true)
				log.WithError(err).Warn("Error installing iptable NOTRACK rules")
			}
			if e.noTrackPort > 0 {
				err = e.owner.Datapath().RemoveNoTrackRules(e.IPv6.String(), e.noTrackPort, true)
				log.WithError(err).Warn("Error removing iptable NOTRACK rules")
			}
		}
		e.noTrackPort = port
	}

	res <- &EndpointRegenerationResult{
		err: nil,
	}
	return
}

// EndpointPolicyVisibilityEvent contains all fields necessary to update the
// visibility policy.
type EndpointPolicyVisibilityEvent struct {
	ep     *Endpoint
	annoCB AnnotationsResolverCB
}

// Handle handles the policy visibility update.
func (ev *EndpointPolicyVisibilityEvent) Handle(res chan interface{}) {
	e := ev.ep

	if err := e.lockAlive(); err != nil {
		// If the endpoint is being deleted, we don't need to update its
		// visibility policy.
		res <- &EndpointRegenerationResult{
			err: nil,
		}
		return
	}

	defer func() {
		// Ensure that policy computation is performed so that endpoint
		// desiredPolicy and realizedPolicy pointers are different. This state
		// is needed to update endpoint policy maps with the policy map state
		// generated from the visibility policy. This can, and should be more
		// elegant in the future.
		e.forcePolicyComputation()
		e.unlock()
	}()

	var (
		nvp *policy.VisibilityPolicy
		err error
	)

	proxyVisibility, err := ev.annoCB(e.K8sNamespace, e.K8sPodName)
	if err != nil {
		res <- &EndpointRegenerationResult{
			err: err,
		}
		return
	}
	if proxyVisibility != "" {
		e.getLogger().Debug("creating visibility policy")
		nvp, err = policy.NewVisibilityPolicy(proxyVisibility)
		if err != nil {
			e.getLogger().WithError(err).Warning("unable to parse annotations into visibility policy; disabling visibility policy for endpoint")
			e.visibilityPolicy = &policy.VisibilityPolicy{
				Ingress: make(policy.DirectionalVisibilityPolicy),
				Egress:  make(policy.DirectionalVisibilityPolicy),
				Error:   err,
			}
			res <- &EndpointRegenerationResult{
				err: nil,
			}
			return
		}
	}

	e.visibilityPolicy = nvp
	res <- &EndpointRegenerationResult{
		err: nil,
	}
	return
}

// EndpointPolicyBandwidthEvent contains all fields necessary to update
// the Pod's bandwidth policy.
type EndpointPolicyBandwidthEvent struct {
	ep     *Endpoint
	annoCB AnnotationsResolverCB
}

// Handle handles the policy bandwidth update.
func (ev *EndpointPolicyBandwidthEvent) Handle(res chan interface{}) {
	var bps uint64

	e := ev.ep
	if err := e.lockAlive(); err != nil {
		// If the endpoint is being deleted, we don't need to
		// update its bandwidth policy.
		res <- &EndpointRegenerationResult{
			err: nil,
		}
		return
	}
	defer func() {
		e.unlock()
	}()

	bandwidthEgress, err := ev.annoCB(e.K8sNamespace, e.K8sPodName)
	if err != nil || !option.Config.EnableBandwidthManager {
		res <- &EndpointRegenerationResult{
			err: err,
		}
		return
	}
	if bandwidthEgress != "" {
		bps, err = bandwidth.GetBytesPerSec(bandwidthEgress)
		if err == nil {
			err = bwmap.Update(e.ID, bps)
		}
	} else {
		err = bwmap.SilentDelete(e.ID)
	}
	if err != nil {
		res <- &EndpointRegenerationResult{
			err: err,
		}
		return
	}

	bpsOld := "inf"
	bpsNew := "inf"
	if e.bps != 0 {
		bpsOld = strconv.FormatUint(e.bps, 10)
	}
	if bps != 0 {
		bpsNew = strconv.FormatUint(bps, 10)
	}
	e.getLogger().Debugf("Updating %s from %s to %s bytes/sec", bandwidth.EgressBandwidth,
		bpsOld, bpsNew)
	e.bps = bps
	res <- &EndpointRegenerationResult{
		err: nil,
	}
}

// InitEventQueue initializes the endpoint's event queue. Note that this
// function does not begin processing events off the queue, as that's left up
// to the caller to call Expose in order to allow other subsystems to access
// the endpoint. This function assumes that the endpoint ID has already been
// allocated!
//
// Having this be a separate function allows us to prepare
// the event queue while the endpoint is being validated (during restoration)
// so that when its metadata is resolved, events can be enqueued (such as
// visibility policy and bandwidth policy).
func (e *Endpoint) InitEventQueue() {
	e.eventQueue = eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", e.ID), option.Config.EndpointQueueSize)
}

// Start assigns a Cilium Endpoint ID to the endpoint and prepares it to
// receive events from other subsystems.
//
// The endpoint must not already be exposed via the endpointmanager prior to
// calling Start(), as it assumes unconditional access over the Endpoint
// object.
func (e *Endpoint) Start(id uint16) {
	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	// 'e.ID' written below, read lock is not enough.
	e.unconditionalLock()
	defer e.unlock()

	e.ID = id
	e.UpdateLogger(map[string]interface{}{
		logfields.EndpointID: e.ID,
	})

	// Start goroutines that are responsible for handling events.
	e.startRegenerationFailureHandler()
	if e.eventQueue == nil {
		e.InitEventQueue()
	}
	e.eventQueue.Run()
	e.getLogger().Info("New endpoint")
}

// Stop cleans up all goroutines managed by this endpoint (EventQueue,
// Controllers).
// This function should be used directly in cleanup functions which aim to stop
// goroutines managed by this endpoint, but without removing BPF maps and
// datapath state (for instance, because the daemon is shutting down but the
// endpoint should remain operational while the daemon is not running).
func (e *Endpoint) Stop() {
	// Since the endpoint is being deleted, we no longer need to run events
	// in its event queue. This is a no-op if the queue has already been
	// closed elsewhere.
	e.eventQueue.Stop()

	// Cancel active controllers for the endpoint tied to e.aliveCtx.
	// Needs to be performed before draining the event queue to allow
	// in-flight functions to act before the Endpoint's underlying resources
	// are removed by the container runtime.
	e.aliveCancel()

	// Wait for the queue to be drained in case an event which is currently
	// running for the endpoint tries to acquire the lock - we cannot be sure
	// what types of events will be pushed onto the EventQueue for an endpoint
	// and when they will happen. After this point, no events for the endpoint
	// will be processed on its EventQueue, specifically regenerations.
	e.eventQueue.WaitToBeDrained()

	// Given that we are deleting the endpoint and that no more builds are
	// going to occur for this endpoint, close the channel which signals whether
	// the endpoint has its BPF program compiled or not to avoid it persisting
	// if anything is blocking on it. If a delete request has already been
	// enqueued for this endpoint, this is a no-op.
	e.closeBPFProgramChannel()
}
