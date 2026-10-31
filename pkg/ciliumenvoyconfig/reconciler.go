// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type envoyOps struct {
	config        CECConfig
	log           *slog.Logger
	xds           resourceMutator
	policyTrigger policyTrigger
	writer        *writer.Writer
	portAllocator PortAllocator

	initDone      chan struct{}
	resourceTable statedb.RWTable[*EnvoyResource]
}

// Initiailizer returns a function that sets up the downstream envoy resource cache
// and starts the reconciler.
func (ops *envoyOps) Initializer(config CECConfig, params reconciler.Params) job.OneShotFunc {
	return func(ctx context.Context, _ cell.Health) error {
		// Wait for EnvoyResources table to be initialized by CEC controller.
		initialized, initDone := ops.resourceTable.Initialized(params.DB.ReadTxn())
		for !initialized {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-initDone:
				initialized = true
			case <-time.After(time.Second):
				pending := ops.resourceTable.PendingInitializers(params.DB.ReadTxn())
				ops.log.Info("Waiting for envoy resources initializers",
					logfields.PendingInitializers, pending)
			}
		}

		// Before starting the reconciler, seed the xDS cache with the resources known so far so
		// that Envoy xDS server can be started with an up-to-date snapshot.
		// Don't wait for ACKs and don't ACK proxy ports, that is done later once the reconciler
		// picks up these resources.
		if err := ops.initializeResources(ctx, params.DB.ReadTxn()); err != nil {
			ops.log.Error("Failed to initialize envoy resource xDS cache", logfields.Error, err)
		}
		close(ops.initDone)

		_, err := reconciler.Register(
			params,
			ops.resourceTable,
			(*EnvoyResource).Clone,
			(*EnvoyResource).SetStatus,
			(*EnvoyResource).GetStatus,
			ops,
			nil,
			reconciler.WithoutPruning(),
			reconciler.WithRetry(config.EnvoyConfigRetryInterval, config.EnvoyConfigRetryInterval),
		)
		return err
	}
}

// initializeResources seeds the xDS cache with the currently known EnvoyResources so that Envoy
// can be started with an up-to-date snapshot before the reconciler starts processing changes.
func (ops *envoyOps) initializeResources(ctx context.Context, txn statedb.ReadTxn) error {
	initCtx, cancel := context.WithTimeout(ctx, maxSyncWaitTime)
	defer cancel()

	merged := xds.NewResources()
	for res := range ops.resourceTable.All(txn) {
		maps.Copy(merged.Listeners, res.Resources.Listeners)
		maps.Copy(merged.Routes, res.Resources.Routes)
		maps.Copy(merged.Clusters, res.Resources.Clusters)
		maps.Copy(merged.Endpoints, res.Resources.Endpoints)
		maps.Copy(merged.Secrets, res.Resources.Secrets)
	}
	return ops.xds.UpdateEnvoyResources(initCtx, xds.NewResources(), merged)
}

// Delete implements reconciler.Operations.
func (ops *envoyOps) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, res *EnvoyResource) error {
	if res.Redirects.Len() > 0 {
		// Remove redirects from services no longer selected by the CEC
		wtxn := ops.writer.WriteTxn()
		defer wtxn.Abort()
		for name := range res.ReconciledRedirects.All() {
			svc, _, found := ops.writer.Services().Get(wtxn, loadbalancer.ServiceByName(name))
			if found {
				svc = svc.Clone()
				svc.ProxyRedirects = nil
				ops.writer.UpsertService(wtxn, svc)
			}
		}
		wtxn.Commit()
	}

	releasedListeners := sets.New[string]()

	var err error
	if prev := res.ReconciledResources; prev != nil {
		// Perform the deletion with the resources that were last successfully reconciled
		// instead of whatever the latest one is (which would have not been pushed to Envoy).
		err = ops.xds.DeleteEnvoyResources(ctx, *prev)

		for _, listener := range prev.Listeners {
			ops.portAllocator.ReleaseProxyPort(listener.Name)
			releasedListeners.Insert(listener.Name)
		}
	}

	// Release the proxy ports of any unreconciled resources
	for _, listener := range res.Resources.Listeners {
		if !releasedListeners.Has(listener.Name) {
			ops.portAllocator.ReleaseProxyPort(listener.Name)
			releasedListeners.Insert(listener.Name)
		}
	}

	if len(releasedListeners) > 0 {
		ops.policyTrigger.TriggerPolicyUpdates()
	}
	return err
}

// Prune implements reconciler.Operations.
func (ops *envoyOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*EnvoyResource, statedb.Revision]) error {
	return nil
}

// isPortBindingError checks if the error is related to port binding failure.
// It checks both ProxyError.Detail and the error message string for common
// port binding failure indicators.
func isPortBindingError(err error) bool {
	if err == nil {
		return false
	}

	if proxyErr, ok := errors.AsType[*xds.ProxyError](err); ok {
		// Check ProxyError.Detail field which contains the actual Envoy error message
		detail := strings.ToLower(proxyErr.Detail)
		if isPortBindingErrorMessage(detail) {
			return true
		}
	}

	// Fallback to checking the error message itself
	errStr := strings.ToLower(err.Error())
	return isPortBindingErrorMessage(errStr)
}

// isPortBindingErrorMessage matches the error strings Envoy emits when a
// listener cannot claim its address. "has duplicate address" is the N/ACK
// rejection Envoy returns when another listener already owns the port, which
// is how a dynamic port allocation collision surfaces outside the agent.
func isPortBindingErrorMessage(errStr string) bool {
	return strings.Contains(errStr, "cannot bind") ||
		strings.Contains(errStr, "address already in use") ||
		strings.Contains(errStr, "eaddrinuse") ||
		strings.Contains(errStr, "has duplicate address")
}

// retryWithNewPorts reallocates dynamically allocated ports and retries UpdateEnvoyResources.
func (ops *envoyOps) retryWithNewPorts(ctx context.Context, prevResources, resources xds.Resources, allocatedListeners set.Set[string]) (xds.Resources, error) {
	newListeners := make(map[string]*envoy_config_listener.Listener, 0)

	for _, listener := range resources.Listeners {
		if listener.GetInternalListener() != nil {
			newListeners[listener.Name] = listener
			continue
		}

		listenerName := listener.Name

		if allocatedListeners.Has(listenerName) {
			newPort, err := ops.portAllocator.ReallocateCRDProxyPort(listenerName)
			if err != nil || newPort == 0 {
				return resources, fmt.Errorf("failed to reallocate proxy port for listener %s: %w", listenerName, err)
			}

			clonedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
			clonedListener.Address, clonedListener.AdditionalAddresses = envoy.GetLocalListenerAddresses(newPort, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())

			ops.log.Info("Reallocated proxy port due to binding failure",
				logfields.Listener, listenerName,
				logfields.ProxyPort, newPort)

			newListeners[clonedListener.Name] = clonedListener
		} else {
			newListeners[listener.Name] = listener
		}
	}

	resources.Listeners = newListeners
	err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)
	return resources, err
}

// Update implements reconciler.Operations.
func (ops *envoyOps) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, res *EnvoyResource) error {
	resources := res.Resources

	ctx, cancel := context.WithTimeout(ctx, ops.config.EnvoyConfigTimeout)
	defer cancel()

	var prevResources xds.Resources
	if res.ReconciledResources != nil {
		prevResources = *res.ReconciledResources

		// Use previously reconciled listener addresses for dynamically allocated ports.
		if !res.AllocatedListeners.Empty() {
			// Published protobufs and the parsed resources may still be in use.
			// Copy before restoring a previously reallocated listener's addresses.
			resources.Listeners = maps.Clone(resources.Listeners)
			for name := range res.AllocatedListeners.Members() {
				if listener, previous := resources.Listeners[name], prevResources.Listeners[name]; listener != nil && previous != nil {
					listener = proto.Clone(listener).(*envoy_config_listener.Listener)
					listener.Address = previous.Address
					listener.AdditionalAddresses = previous.AdditionalAddresses
					resources.Listeners[name] = listener
				}
			}
		}
	}

	err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)
	reallocated := false

	if err != nil && isPortBindingError(err) && !res.AllocatedListeners.Empty() {
		ops.log.Warn("Port binding failed, attempting to reallocate ports and retry",
			logfields.Error, err)

		updatedResources, retryErr := ops.retryWithNewPorts(ctx, prevResources, resources, res.AllocatedListeners)
		if retryErr != nil {
			return fmt.Errorf("failed to reallocate ports after binding failure: %w (original error: %w)", retryErr, err)
		}
		resources = updatedResources
		reallocated = true
		err = nil
	}

	if err == nil {
		// The update and its required waits have succeeded, including any listener
		// recreation retries. Only now acquire references for new ports.
		for name := range res.AllocatedListeners.Members() {
			listener := resources.Listeners[name]
			if listener == nil {
				continue
			}
			previous := prevResources.Listeners[name].GetAddress().GetSocketAddress()
			if !reallocated && previous != nil && previous.GetPortValue() == listener.GetAddress().GetSocketAddress().GetPortValue() {
				// Additional-address changes do not acquire another primary port.
				continue
			}
			if err := ops.portAllocator.AckProxyPortWithReference(ctx, name); err != nil {
				ops.log.Warn("Failed to acknowledge proxy port",
					logfields.Listener, name,
					logfields.Error, err)
			}
		}

		if prevResources.ListenersAddedOrDeleted(&resources) {
			ops.policyTrigger.TriggerPolicyUpdates()
		}

		res.ReconciledResources = &resources

		// With the envoy resources successfully pushed to Envoy, set the proxy redirections
		// for the associated services.
		if res.Redirects.Len() > 0 || res.ReconciledRedirects.Len() > 0 {
			wtxn := ops.writer.WriteTxn()
			orphanRedirects := res.ReconciledRedirects
			for name, redirects := range res.Redirects.All() {
				svc, _, found := ops.writer.Services().Get(wtxn, loadbalancer.ServiceByName(name))
				if found && !svc.ProxyRedirects.Equal(redirects) {
					svc = svc.Clone()
					svc.ProxyRedirects = redirects
					ops.writer.UpsertService(wtxn, svc)
				}
				orphanRedirects = orphanRedirects.Delete(name)
			}
			for name := range orphanRedirects.All() {
				if _, found := res.Redirects.Get(name); !found {
					svc, _, found := ops.writer.Services().Get(wtxn, loadbalancer.ServiceByName(name))
					if found {
						svc = svc.Clone()
						svc.ProxyRedirects = nil
						ops.writer.UpsertService(wtxn, svc)
					}
				}
			}
			wtxn.Commit()
			res.ReconciledRedirects = res.Redirects
		}
	}
	return err
}

var _ reconciler.Operations[*EnvoyResource] = &envoyOps{}

func registerEnvoyReconciler(
	log *slog.Logger,
	config CECConfig,
	xds resourceMutator,
	pt policyTrigger,
	params reconciler.Params,
	writer *writer.Writer,
	envoyResources statedb.RWTable[*EnvoyResource],
	portAllocator PortAllocator,
	fence regeneration.Fence,
) {
	ops := &envoyOps{
		config:        config,
		log:           log,
		xds:           xds,
		writer:        writer,
		policyTrigger: pt,
		portAllocator: portAllocator,

		initDone:      make(chan struct{}),
		resourceTable: envoyResources,
	}

	// Register initializer to block endpoint regeneration before Envoy cache is initialized.
	fence.Add("ciliumenvoyconfig", func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, maxSyncWaitTime)
		defer cancel()

		select {
		case <-ctx.Done():
			log.Error("Failed waiting on CiliumEnvoyConfig reconciler initialization", logfields.Error, ctx.Err())
		case <-ops.initDone:
		}
		return nil
	})
	params.JobGroup.Add(job.OneShot("envoy-reconciler", ops.Initializer(config, params)))
}

type policyTriggerWrapper struct{ updater *policy.Updater }

func (p policyTriggerWrapper) TriggerPolicyUpdates() {
	p.updater.TriggerPolicyUpdates("Envoy Listeners changed")
}

func newPolicyTrigger(log *slog.Logger, updater *policy.Updater) policyTrigger {
	return policyTriggerWrapper{updater}
}

type resourceMutator interface {
	DeleteEnvoyResources(ctx context.Context, resources xds.Resources) error
	UpdateEnvoyResources(ctx context.Context, old xds.Resources, new xds.Resources) error
}

type policyTrigger interface {
	TriggerPolicyUpdates()
}
