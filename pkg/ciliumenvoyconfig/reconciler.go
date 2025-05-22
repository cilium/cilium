// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
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

// Update implements reconciler.Operations.
func (ops *envoyOps) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, res *EnvoyResource) error {
	resources := res.Resources

	ctx, cancel := context.WithTimeout(ctx, ops.config.EnvoyConfigTimeout)
	defer cancel()

	var prevResources envoy.Resources
	if res.ReconciledResources != nil {
		prevResources = *res.ReconciledResources
	}

	err := ops.xds.UpdateEnvoyResources(ctx, prevResources, resources)
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
