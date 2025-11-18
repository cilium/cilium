// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

type envoyOps struct {
	config        CECConfig
	log           *slog.Logger
	xds           resourceMutator
	policyTrigger policyTrigger
	writer        *writer.Writer
	portAllocator PortAllocator
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
				svc.ProxyRedirect = nil
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

	var proxyErr *xds.ProxyError
	if errors.As(err, &proxyErr) {
		// Check ProxyError.Detail field which contains the actual Envoy error message
		detail := strings.ToLower(proxyErr.Detail)
		if strings.Contains(detail, "cannot bind") ||
			strings.Contains(detail, "address already in use") ||
			strings.Contains(detail, "eaddrinuse") {
			return true
		}
	}

	// Fallback to checking the error message itself
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "cannot bind") ||
		strings.Contains(errStr, "address already in use") ||
		strings.Contains(errStr, "eaddrinuse")
}

// retryWithNewPorts reallocates dynamically allocated ports and retries UpdateEnvoyResources.
func (ops *envoyOps) retryWithNewPorts(ctx context.Context, prevResources, resources envoy.Resources) (envoy.Resources, error) {
	newListeners := make([]*envoy_config_listener.Listener, 0, len(resources.Listeners))

	for _, listener := range resources.Listeners {
		if listener.GetInternalListener() != nil {
			newListeners = append(newListeners, listener)
			continue
		}

		listenerName := listener.Name

		if resources.PortAllocationCallbacks != nil && resources.PortAllocationCallbacks[listenerName] != nil {
			newPort, err := ops.portAllocator.ReallocateCRDProxyPort(listenerName)
			if err != nil || newPort == 0 {
				return resources, fmt.Errorf("failed to reallocate proxy port for listener %s: %w", listenerName, err)
			}

			clonedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
			clonedListener.Address, clonedListener.AdditionalAddresses = envoy.GetLocalListenerAddresses(newPort, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())

			ops.log.Info("Reallocated proxy port due to binding failure",
				logfields.Listener, listenerName,
				logfields.ProxyPort, newPort)

			if resources.PortAllocationCallbacks == nil {
				resources.PortAllocationCallbacks = make(map[string]func(context.Context) error)
			}
			resources.PortAllocationCallbacks[listenerName] = func(ctx context.Context) error {
				return ops.portAllocator.AckProxyPortWithReference(ctx, listenerName)
			}

			newListeners = append(newListeners, clonedListener)
		} else {
			newListeners = append(newListeners, listener)
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

	var prevResources envoy.Resources
	if res.ReconciledResources != nil {
		prevResources = *res.ReconciledResources

		// Use previously reconciled listener addresses for dynamically allocated ports.
		if resources.PortAllocationCallbacks != nil {
			reconciledListenersByName := make(map[string]*envoy_config_listener.Listener)
			for _, l := range prevResources.Listeners {
				reconciledListenersByName[l.Name] = l
			}
			for i, l := range resources.Listeners {
				if _, hasCb := resources.PortAllocationCallbacks[l.Name]; hasCb {
					if reconciledL, ok := reconciledListenersByName[l.Name]; ok {
						resources.Listeners[i].Address = reconciledL.Address
						resources.Listeners[i].AdditionalAddresses = reconciledL.AdditionalAddresses
					}
				}
			}
		}
	}

	err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)

	if err != nil && isPortBindingError(err) {
		hasDynamicallyAllocatedPorts := false
		if len(resources.PortAllocationCallbacks) > 0 {
			for _, listener := range resources.Listeners {
				if listener.GetInternalListener() != nil {
					continue
				}
				if _, exists := resources.PortAllocationCallbacks[listener.Name]; exists {
					hasDynamicallyAllocatedPorts = true
					break
				}
			}
		}

		if hasDynamicallyAllocatedPorts {
			ops.log.Warn("Port binding failed, attempting to reallocate ports and retry",
				logfields.Error, err)

			updatedResources, retryErr := ops.retryWithNewPorts(ctx, prevResources, resources)
			if retryErr != nil {
				return fmt.Errorf("failed to reallocate ports after binding failure: %w (original error: %w)", retryErr, err)
			}
			resources = updatedResources
			err = nil
		}
	}

	if err == nil {
		if prevResources.ListenersAddedOrDeleted(&resources) {
			ops.policyTrigger.TriggerPolicyUpdates()
		}

		res.ReconciledResources = &resources
		res.ReconciledResources.PortAllocationCallbacks = nil

		// With the envoy resources successfully pushed to Envoy, set the proxy redirections
		// for the associated services.
		if res.Redirects.Len() > 0 || res.ReconciledRedirects.Len() > 0 {
			wtxn := ops.writer.WriteTxn()
			orphanRedirects := res.ReconciledRedirects
			for name, redirect := range res.Redirects.All() {
				svc, _, found := ops.writer.Services().Get(wtxn, loadbalancer.ServiceByName(name))
				if found && !svc.ProxyRedirect.Equal(redirect) {
					svc = svc.Clone()
					svc.ProxyRedirect = redirect
					ops.writer.UpsertService(wtxn, svc)
				}
				orphanRedirects = orphanRedirects.Delete(name)
			}
			for name := range orphanRedirects.All() {
				if _, found := res.Redirects.Get(name); !found {
					svc, _, found := ops.writer.Services().Get(wtxn, loadbalancer.ServiceByName(name))
					if found {
						svc = svc.Clone()
						svc.ProxyRedirect = nil
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
) error {
	ops := &envoyOps{
		config:        config,
		log:           log,
		xds:           xds,
		writer:        writer,
		policyTrigger: pt,
		portAllocator: portAllocator,
	}
	_, err := reconciler.Register(
		params,
		envoyResources,
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

type policyTriggerWrapper struct{ updater *policy.Updater }

func (p policyTriggerWrapper) TriggerPolicyUpdates() {
	p.updater.TriggerPolicyUpdates("Envoy Listeners changed")
}

func newPolicyTrigger(log *slog.Logger, updater *policy.Updater) policyTrigger {
	return policyTriggerWrapper{updater}
}

type resourceMutator interface {
	DeleteEnvoyResources(context.Context, envoy.Resources) error
	UpdateEnvoyResources(context.Context, envoy.Resources, envoy.Resources) error
}

type policyTrigger interface {
	TriggerPolicyUpdates()
}
