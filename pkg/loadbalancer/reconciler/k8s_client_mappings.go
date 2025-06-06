// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// FIXME move to pkg/k8s/client/ha or something.
func registerK8sAPIServiceMappingsUpdater(
	jg job.Group,
	log *slog.Logger,
	db *statedb.DB,
	fes statedb.Table[*loadbalancer.Frontend],
) {
	jg.Add(
		job.OneShot(
			"update-k8s-api-service-mappings",
			func(ctx context.Context, health cell.Health) error {
				for {
					fe, _, watch, found := fes.GetWatch(
						db.ReadTxn(),
						loadbalancer.FrontendByServiceName(loadbalancer.ServiceName{
							Name:      "kubernetes",
							Namespace: "default",
						}))
					if found {
						updateK8sAPIServiceMappings(log, fe)
					}

					select {
					case <-ctx.Done():
						return nil
					case <-watch:
					}
				}
			}))
}

// updateK8sAPIServiceMappings updates service to endpoints mapping.
// This is currently used for supporting high availability for kubeapi-server.
func updateK8sAPIServiceMappings(log *slog.Logger, fe *loadbalancer.Frontend) {
	var mapping client.K8sServiceEndpointMapping
	mapping.Service = fe.Address.AddrString()
	for be := range fe.Backends {
		mapping.Endpoints = append(mapping.Endpoints, be.Address.AddrString())
	}
	log.Info("writing kubernetes service mapping",
		logfields.Entry, mapping,
	)
	client.UpdateK8sAPIServerEntry(log, mapping)
}
