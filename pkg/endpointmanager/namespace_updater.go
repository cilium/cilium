// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpoint"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

func registerNamespaceUpdater(log *slog.Logger, jg job.Group, db *statedb.DB, namespaces statedb.Table[k8sTables.Namespace], em EndpointManager) {
	nsUpdater := namespaceUpdater{
		oldIdtyLabels:   make(map[string]labels.Labels),
		oldDelegations:  make(map[string]map[string]string),
		endpointManager: em,
		log:             log,
		db:              db,
		namespaces:      namespaces,
	}
	jg.Add(job.OneShot(
		"namespace-updater",
		nsUpdater.run,
	))
}

type namespaceUpdater struct {
	oldIdtyLabels   map[string]labels.Labels
	oldDelegations  map[string]map[string]string // Track the delegation annotations (see endpoint.DelegatedAnnotations) per namespace
	endpointManager EndpointManager
	log             *slog.Logger
	db              *statedb.DB
	namespaces      statedb.Table[k8sTables.Namespace]
}

func getNamespaceLabels(ns k8sTables.Namespace) labels.Labels {
	lbls := ns.Labels
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func (u *namespaceUpdater) run(ctx context.Context, health cell.Health) error {
	// Use Changes() instead of AllWatch() to properly track namespace deletions.
	// This ensures the oldIdtyLabels and oldSIPAllowAnno maps are cleaned up
	// when namespaces are deleted, preventing memory leaks and stale data issues.
	wtxn := u.db.WriteTxn(u.namespaces)
	changeIter, err := u.namespaces.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	for {
		changes, watch := changeIter.Next(u.db.ReadTxn())
		for change := range changes {
			if change.Deleted {
				// Clean up tracking maps when namespace is deleted
				delete(u.oldIdtyLabels, change.Object.Name)
				delete(u.oldDelegations, change.Object.Name)
			} else {
				u.update(change.Object)
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

func (u *namespaceUpdater) update(newNS k8sTables.Namespace) error {
	newLabels := getNamespaceLabels(newNS)

	oldIdtyLabels := u.oldIdtyLabels[newNS.Name]
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Check which delegation annotations (e.g. DelegateSourceIPVerification) changed
	oldDelegations := u.oldDelegations[newNS.Name]
	changedDelegated := endpoint.FilterDelegatedAnnotations(func(da endpoint.DelegatedAnnotation) bool {
		return newNS.Annotations[da.NamespaceKey] != oldDelegations[da.NamespaceKey]
	})

	labelsChanged := !oldIdtyLabels.DeepEqual(&newIdtyLabels)

	// Do not perform any operations if neither labels nor delegation annotations changed.
	if !labelsChanged && len(changedDelegated) == 0 {
		return nil
	}

	eps := u.endpointManager.GetEndpointsByNamespace(newNS.Name)
	failed := false
	ciliumIdentityMaxJitter := option.Config.CiliumIdentityMaxJitter
	for _, ep := range eps {
		// Handle identity label updates
		if labelsChanged {
			err := ep.ModifyIdentityLabels(labels.LabelSourceK8s, newIdtyLabels, oldIdtyLabels, ciliumIdentityMaxJitter)
			if err != nil {
				u.log.Warn("unable to update endpoint with new identity labels from namespace labels",
					logfields.Error, err,
					logfields.EndpointID, ep.ID)
				failed = true
			}
		}

		// Handle delegation annotation changes - re-evaluate all endpoints in this namespace
		if len(changedDelegated) > 0 {
			changed := false
			// Get pod annotations from the endpoint's cached pod
			pod := ep.GetPod()
			var podAnno map[string]string
			if pod != nil {
				podAnno = pod.Annotations
			}

			// Re-apply the settings with the new namespace annotations
			for _, da := range ep.ApplyDelegatedAnnotations(changedDelegated, podAnno, newNS.Annotations) {
				u.log.Info("Namespace delegation annotation changed, regenerating endpoint",
					logfields.K8sNamespace, newNS.Name,
					logfields.EndpointID, ep.ID,
					logfields.Option, da.Option,
					logfields.Value, newNS.Annotations[da.NamespaceKey])
				changed = true
			}
			// Trigger datapath regeneration if any setting changed
			if changed {
				ep.RegenerateDatapathIfAlive("namespace delegation annotation changed")
			}
		}
	}
	if failed {
		return errors.New("unable to update some endpoints with new namespace labels")
	}
	u.oldIdtyLabels[newNS.Name] = newIdtyLabels
	newDelegations := make(map[string]string, len(endpoint.DelegatedAnnotations))
	for _, da := range endpoint.DelegatedAnnotations {
		newDelegations[da.NamespaceKey] = newNS.Annotations[da.NamespaceKey]
	}
	u.oldDelegations[newNS.Name] = newDelegations
	return nil
}
