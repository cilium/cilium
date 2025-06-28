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

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

func registerNamespaceUpdater(log *slog.Logger, jg job.Group, db *statedb.DB, namespaces statedb.Table[daemonk8s.Namespace], em EndpointManager) {
	nsUpdater := namespaceUpdater{
		oldIdtyLabels:   make(map[string]labels.Labels),
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
	endpointManager EndpointManager
	log             *slog.Logger
	db              *statedb.DB
	namespaces      statedb.Table[daemonk8s.Namespace]
}

func getNamespaceLabels(ns daemonk8s.Namespace) labels.Labels {
	lbls := ns.Labels
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func (u *namespaceUpdater) run(ctx context.Context, health cell.Health) error {
	for {
		namespaces, watch := u.namespaces.AllWatch(u.db.ReadTxn())
		for ns := range namespaces {
			u.update(ns)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

func (u *namespaceUpdater) update(newNS daemonk8s.Namespace) error {
	newLabels := getNamespaceLabels(newNS)

	oldIdtyLabels := u.oldIdtyLabels[newNS.Name]
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations if the old labels are the same as
	// the new labels.
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return nil
	}

	eps := u.endpointManager.GetEndpoints()
	failed := false
	ciliumIdentityMaxJitter := option.Config.CiliumIdentityMaxJitter
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if newNS.Name == epNS {
			err := ep.ModifyIdentityLabels(labels.LabelSourceK8s, newIdtyLabels, oldIdtyLabels, ciliumIdentityMaxJitter)
			if err != nil {
				u.log.Warn("unable to update endpoint with new identity labels from namespace labels",
					logfields.Error, err,
					logfields.EndpointID, ep.ID)
				failed = true
			}
		}
	}
	if failed {
		return errors.New("unable to update some endpoints with new namespace labels")
	}
	u.oldIdtyLabels[newNS.Name] = newIdtyLabels
	return nil
}
