// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// trackInstanceStateChange is a goroutine that listens on the tracker channel and signals state reconciler.
// It will be returned when tracker go routine is closed.
func (m *BGPRouterManager) trackInstanceStateChange(instance string, tracker chan struct{}) {
	for range tracker {
		m.Logger.WithField(types.InstanceLogField, instance).Debug("Event change detected for instance")

		// insert this instance in pending state modified list
		// we can be waiting here for long since it is also taken by main reconcile loop.
		// We do not want to modify PendingInstances set while main reconcile loop is processing it.
		// Any new events will level trigger tracker channel and move along.
		m.state.pendingInstancesMutex.Lock()
		m.state.pendingInstances.Insert(instance)
		m.state.pendingInstancesMutex.Unlock()

		// notify the main reconcile loop that the state for some instance has changed
		// It is okay if that channel is full, there can be multiple instances trying to
		// notify the main reconcile loop that the state has changed.
		select {
		case m.state.reconcileSignal <- struct{}{}:
		default:
		}
	}

	// tracker is close, signal the main reconcile loop that this instance is deleted so it
	// can do any necessary cleanup.
	m.state.instanceDeletionSignal <- instance
	m.Logger.WithField(types.InstanceLogField, instance).Debug("Instance deleted, stopping state tracker")
}

// reconcileState is the main loop that reconciles the state of all instances that have pending state changes.
// It will take StateMutex lock to process the pending instances and then reset the pending instances set.
// Any new state changes will be blocked till this method completes.
func (m *BGPRouterManager) reconcileState(ctx context.Context) {
	// we lock the state mutex so no changes to PendingInstances set can be made while we are processing it.
	m.state.pendingInstancesMutex.Lock()
	defer m.state.pendingInstancesMutex.Unlock()

	m.Logger.WithField("UpdatedInstances", m.state.pendingInstances.Len()).
		Debug("Reconciling state for instances with pending state changes")

	// process all pending instances
	for instanceName := range m.state.pendingInstances {
		m.reconcileInstanceState(ctx, instanceName)
	}

	// reset the pending states set as we have processed all the instances
	// that had state changes. New state changes will be added to this set by the
	// trackInstanceStateChange function.
	m.state.pendingInstances = sets.New[string]()
}

func (m *BGPRouterManager) reconcileInstanceDeletion(ctx context.Context, instanceName string) {
	m.RLock()
	defer m.RUnlock()

	for _, stateReconciler := range m.state.reconcilers {
		err := stateReconciler.Reconcile(ctx, reconcilerv2.StateReconcileParams{
			ConfigMode:      m.ConfigMode,
			DeletedInstance: instanceName,
		})
		if err != nil {
			m.Logger.WithError(err).
				WithField(types.InstanceLogField, instanceName).
				Error("Error while reconciling state")
		}
	}
}

// reconcileInstanceState reconciles the state of a single instance. It will take read lock
// on BGPInstances lock as we are inspecting BGP instances.
// It will call all the state reconcilers to reconcile the state of the instance.
func (m *BGPRouterManager) reconcileInstanceState(ctx context.Context, instanceName string) {
	m.RLock()
	defer m.RUnlock()

	instance, exists := m.BGPInstances[instanceName]
	if !exists {
		m.Logger.WithField(types.InstanceLogField, instanceName).
			Warning("instance not found while reconciling state")
		return
	}

	for _, stateReconciler := range m.state.reconcilers {
		err := stateReconciler.Reconcile(ctx, reconcilerv2.StateReconcileParams{
			ConfigMode:      m.ConfigMode,
			UpdatedInstance: instance,
		})
		if err != nil {
			m.Logger.WithError(err).
				WithField(types.InstanceLogField, instanceName).
				Error("Error while reconciling state")
		}
	}
}
