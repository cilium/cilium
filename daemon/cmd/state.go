// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"github.com/cilium/cilium/pkg/controller"
)

var syncLBMapsControllerGroup = controller.NewGroup("sync-lb-maps-with-k8s-services")

func (d *Daemon) removeStaleK8sServices() {
	// Also wait for all shared services to be synchronized with the
	// datapath before proceeding.
	if d.clustermesh != nil {
		err := d.clustermesh.ServicesSynced(d.ctx)
		if err != nil {
			log.WithError(err).Fatal("timeout while waiting for all clusters to be locally synchronized")
		}
		log.Debug("all clusters have been correctly synchronized locally")
	}
	// Start controller which removes any leftover Kubernetes
	// services that may have been deleted while Cilium was not
	// running. Once this controller succeeds, because it has no
	// RunInterval specified, it will not run again unless updated
	// elsewhere. This means that if, for instance, a user manually
	// adds a service via the CLI into the BPF maps, that it will
	// not be cleaned up by the daemon until it restarts.
	controller.NewManager().UpdateController(
		"sync-lb-maps-with-k8s-services",
		controller.ControllerParams{
			Group: syncLBMapsControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return d.svc.SyncWithK8sFinished(d.k8sWatcher.K8sSvcCache.EnsureService)
			},
			Context: d.ctx,
		},
	)
}
