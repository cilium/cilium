// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterReaderFactory provides an interface that can be implemented to provide custom
// ClusterReader implementations in the StatusPoller.
type ClusterReaderFactory interface {
	New(reader client.Reader, mapper meta.RESTMapper, identifiers object.ObjMetadataSet) (ClusterReader, error)
}

type ClusterReaderFactoryFunc func(client.Reader, meta.RESTMapper, object.ObjMetadataSet) (ClusterReader, error)

func (c ClusterReaderFactoryFunc) New(r client.Reader, m meta.RESTMapper, ids object.ObjMetadataSet) (ClusterReader, error) {
	return c(r, m, ids)
}

// PollerEngine provides functionality for polling a cluster for status of a set of resources.
type PollerEngine struct {
	Reader               client.Reader
	Mapper               meta.RESTMapper
	StatusReaders        []StatusReader
	DefaultStatusReader  StatusReader
	ClusterReaderFactory ClusterReaderFactory
}

// Poll will create a new statusPollerRunner that will poll all the resources provided and report their status
// back on the event channel returned. The statusPollerRunner can be cancelled at any time by cancelling the
// context passed in.
// The context can be used to stop the polling process by using timeout, deadline or
// cancellation.
func (s *PollerEngine) Poll(ctx context.Context, identifiers object.ObjMetadataSet, options Options) <-chan event.Event {
	eventChannel := make(chan event.Event)

	go func() {
		defer close(eventChannel)

		err := s.validateIdentifiers(identifiers)
		if err != nil {
			handleError(eventChannel, err)
			return
		}

		clusterReader, err := s.ClusterReaderFactory.New(s.Reader, s.Mapper, identifiers)
		if err != nil {
			handleError(eventChannel, fmt.Errorf("error creating new ClusterReader: %w", err))
			return
		}

		runner := &statusPollerRunner{
			clusterReader:            clusterReader,
			statusReaders:            s.StatusReaders,
			defaultStatusReader:      s.DefaultStatusReader,
			identifiers:              identifiers,
			previousResourceStatuses: make(map[object.ObjMetadata]*event.ResourceStatus),
			eventChannel:             eventChannel,
			pollingInterval:          options.PollInterval,
		}
		runner.Run(ctx)
	}()

	return eventChannel
}

func handleError(eventChannel chan event.Event, err error) {
	eventChannel <- event.Event{
		Type:  event.ErrorEvent,
		Error: err,
	}
}

// validateIdentifiers makes sure that all namespaced resources
// passed in
func (s *PollerEngine) validateIdentifiers(identifiers object.ObjMetadataSet) error {
	for _, id := range identifiers {
		mapping, err := s.Mapper.RESTMapping(id.GroupKind)
		if err != nil {
			// If we can't find a match, just keep going. This can happen
			// if CRDs and CRs are applied at the same time.
			if meta.IsNoMatchError(err) {
				continue
			}
			return err
		}
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace && id.Namespace == "" {
			return fmt.Errorf("resource %s %s is namespace scoped, but namespace is not set",
				id.GroupKind.String(), id.Name)
		}
	}
	return nil
}

// Options contains the different parameters that can be used to adjust the
// behavior of the PollerEngine.
// Timeout is not one of the options here as this should be accomplished by
// setting a timeout on the context: https://golang.org/pkg/context/
type Options struct {

	// PollInterval defines how often the PollerEngine should poll the cluster for the latest
	// state of the resources.
	PollInterval time.Duration
}

// statusPollerRunner is responsible for polling of a set of resources. Each call to Poll will create
// a new statusPollerRunner, which means we can keep state in the runner and all data will only be accessed
// by a single goroutine, meaning we don't need synchronization.
// The statusPollerRunner uses an implementation of the ClusterReader interface to talk to the
// kubernetes cluster. Currently this can be either the cached ClusterReader that syncs all needed resources
// with LIST calls before each polling loop, or the normal ClusterReader that just forwards each call
// to the client.Reader from controller-runtime.
type statusPollerRunner struct {
	// clusterReader is the interface for fetching and listing resources from the cluster. It can be implemented
	// to make call directly to the cluster or use caching to reduce the number of calls to the cluster.
	clusterReader ClusterReader

	// statusReaders contains the resource specific statusReaders. These will contain logic for how to
	// compute status for specific GroupKinds. These will use an ClusterReader to fetch
	// status of a resource and any generated resources.
	statusReaders []StatusReader

	// defaultStatusReader is the generic engine that is used for all GroupKinds that
	// doesn't have a specific engine in the statusReaders map.
	defaultStatusReader StatusReader

	// identifiers contains the set of identifiers for the resources that should be polled.
	// Each resource is identified by GroupKind, namespace and name.
	identifiers object.ObjMetadataSet

	// previousResourceStatuses keeps track of the last event for each
	// of the polled resources. This is used to make sure we only
	// send events on the event channel when something has actually changed.
	previousResourceStatuses map[object.ObjMetadata]*event.ResourceStatus

	// eventChannel is a channel where any updates to the status of resources
	// will be sent. The caller of Poll will listen for updates.
	eventChannel chan event.Event

	// pollingInterval determines how often we should poll the cluster for
	// the latest state of resources.
	pollingInterval time.Duration
}

// Run starts the polling loop of the statusReaders.
func (r *statusPollerRunner) Run(ctx context.Context) {
	// Sets up ticker that will trigger the regular polling loop at a regular interval.
	ticker := time.NewTicker(r.pollingInterval)
	defer func() {
		ticker.Stop()
	}()

	err := r.syncAndPoll(ctx)
	if err != nil {
		r.handleSyncAndPollErr(err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// First sync and then compute status for all resources.
			err := r.syncAndPoll(ctx)
			if err != nil {
				r.handleSyncAndPollErr(err)
				return
			}
		}
	}
}

// handleSyncAndPollErr decides what to do if we encounter an error while
// fetching resources to compute status. Errors are usually returned
// as an ErrorEvent, but we handle context cancellation or deadline exceeded
// differently since they aren't really errors, but a signal that the
// process should shut down.
func (r *statusPollerRunner) handleSyncAndPollErr(err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	r.eventChannel <- event.Event{
		Type:  event.ErrorEvent,
		Error: err,
	}
}

func (r *statusPollerRunner) syncAndPoll(ctx context.Context) error {
	// First trigger a sync of the ClusterReader. This may or may not actually
	// result in calls to the cluster, depending on the implementation.
	// If this call fails, there is no clean way to recover, so we just return an ErrorEvent
	// and shut down.
	err := r.clusterReader.Sync(ctx)
	if err != nil {
		return err
	}
	// Poll all resources and compute status. If the polling of resources has completed (based
	// on information from the StatusAggregator and the value of pollUntilCancelled), we send
	// a CompletedEvent and return.
	return r.pollStatusForAllResources(ctx)
}

// pollStatusForAllResources iterates over all the resources in the set and delegates
// to the appropriate engine to compute the status.
func (r *statusPollerRunner) pollStatusForAllResources(ctx context.Context) error {
	for _, id := range r.identifiers {
		// Check if the context has been cancelled on every iteration.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		gk := id.GroupKind
		statusReader := r.statusReaderForGroupKind(gk)
		resourceStatus, err := statusReader.ReadStatus(ctx, r.clusterReader, id)
		if err != nil {
			return err
		}
		if r.isUpdatedResourceStatus(resourceStatus) {
			r.previousResourceStatuses[id] = resourceStatus
			r.eventChannel <- event.Event{
				Type:     event.ResourceUpdateEvent,
				Resource: resourceStatus,
			}
		}
	}
	return nil
}

func (r *statusPollerRunner) statusReaderForGroupKind(gk schema.GroupKind) StatusReader {
	for _, sr := range r.statusReaders {
		if sr.Supports(gk) {
			return sr
		}
	}
	return r.defaultStatusReader
}

func (r *statusPollerRunner) isUpdatedResourceStatus(resourceStatus *event.ResourceStatus) bool {
	oldResourceStatus, found := r.previousResourceStatuses[resourceStatus.Identifier]
	if !found {
		return true
	}
	return !event.ResourceStatusEqual(resourceStatus, oldResourceStatus)
}
