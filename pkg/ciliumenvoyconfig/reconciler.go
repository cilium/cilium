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
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"

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
// The controller releases CRD listener ports when removing the resource from
// StateDB and triggers policy updates after commit if any ports were released.
// Delete handles service redirects and reconciled xDS cleanup, which may be
// retried without repeating port release or policy notification.
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

	if prev := res.ReconciledResources; prev != nil {
		// Perform the deletion with the resources that were last successfully reconciled
		// instead of whatever the latest one is (which would have not been pushed to Envoy).
		if err := ops.xds.DeleteEnvoyResources(ctx, *prev); err != nil {
			return err
		}
	}
	return nil
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

// setListenerPort updates the addresses and policy identity of a caller-owned listener.
func setListenerPort(listener *envoy_config_listener.Listener, port uint16) error {
	listener.Address, listener.AdditionalAddresses = envoy.GetLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
	// Policy rules identify CRD listeners by their proxy port.
	for _, filter := range listener.ListenerFilters {
		if filter.Name != ciliumBPFMetadataListenerFilterName {
			continue
		}
		var metadata cilium.BpfMetadata
		if err := filter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
			return fmt.Errorf("reading BPF metadata for listener %s: %w", listener.Name, err)
		}
		metadata.ProxyId = uint32(port)
		if err := filter.GetTypedConfig().MarshalFrom(&metadata); err != nil {
			return fmt.Errorf("updating BPF metadata for listener %s: %w", listener.Name, err)
		}
	}
	return nil
}

// retryWithNewPorts reallocates unconfirmed listener ports and retries UpdateEnvoyResources.
func (ops *envoyOps) retryWithNewPorts(ctx context.Context, prevResources, resources xds.Resources, allocationsToAck set.Set[string]) (xds.Resources, error) {
	newListeners := make(map[string]*envoy_config_listener.Listener, 0)

	for _, listener := range resources.Listeners {
		if listener.GetInternalListener() != nil {
			newListeners[listener.Name] = listener
			continue
		}

		listenerName := listener.Name

		if allocationsToAck.Has(listenerName) {
			newPort, err := ops.portAllocator.ReallocateCRDProxyPort(listenerName)
			if err != nil || newPort == 0 {
				return resources, fmt.Errorf("failed to reallocate proxy port for listener %s: %w", listenerName, err)
			}

			clonedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
			if err := setListenerPort(clonedListener, newPort); err != nil {
				return resources, err
			}

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
	}

	var allocationsToAck set.Set[string]
	var updatedListeners map[string]*envoy_config_listener.Listener
	for name := range res.AllocatedListeners.Members() {
		listener := resources.Listeners[name]
		if listener == nil {
			continue
		}
		// The parsed address may predate a bind retry, including a failed retry.
		port, err := ops.portAllocator.AllocateCRDProxyPort(name)
		if err != nil || port == 0 {
			return fmt.Errorf("listener port allocation for %q failed: %w", name, err)
		}
		previous := prevResources.Listeners[name].GetAddress().GetSocketAddress()
		if !res.ReconciledAllocatedListeners.Has(name) || previous == nil || previous.GetPortValue() != uint32(port) {
			allocationsToAck.Insert(name)
		}
		if listener.GetAddress().GetSocketAddress().GetPortValue() != uint32(port) {
			if updatedListeners == nil {
				updatedListeners = maps.Clone(resources.Listeners)
			}
			listener = proto.Clone(listener).(*envoy_config_listener.Listener)
			if err := setListenerPort(listener, port); err != nil {
				return err
			}
			updatedListeners[name] = listener
		}
	}
	if updatedListeners != nil {
		resources.Listeners = updatedListeners
	}

	err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)

	if err != nil && isPortBindingError(err) && !allocationsToAck.Empty() {
		ops.log.Warn("Port binding failed, attempting to reallocate ports and retry",
			logfields.Error, err)

		updatedResources, retryErr := ops.retryWithNewPorts(ctx, prevResources, resources, allocationsToAck)
		if retryErr != nil {
			return fmt.Errorf("failed to reallocate ports after binding failure: %w (original error: %w)", retryErr, err)
		}
		resources = updatedResources
		err = nil
	}

	if err == nil {
		portsChanged := false
		// The update and its required waits have succeeded, including any listener
		// recreation retries. Only now make the new ports available to redirects.
		for name := range allocationsToAck.Members() {
			if ackErr := ops.portAllocator.AckCRDProxyPort(ctx, name); ackErr != nil {
				err = errors.Join(err, fmt.Errorf("acknowledging proxy port %q: %w", name, ackErr))
				continue
			}
			portsChanged = true
		}
		if err != nil {
			if portsChanged {
				ops.policyTrigger.TriggerPolicyUpdates()
			}
			return err
		}
		for name := range res.ReconciledAllocatedListeners.Members() {
			if !res.AllocatedListeners.Has(name) {
				if err := ops.portAllocator.ReleaseCRDProxyPort(name); err != nil {
					ops.log.Warn("Failed to release proxy port",
						logfields.Listener, name,
						logfields.Error, err)
				} else {
					portsChanged = true
				}
			}
		}

		if portsChanged || prevResources.ListenersAddedOrDeleted(&resources) {
			ops.policyTrigger.TriggerPolicyUpdates()
		}

		res.ReconciledResources = &resources
		res.ReconciledAllocatedListeners = res.AllocatedListeners

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
