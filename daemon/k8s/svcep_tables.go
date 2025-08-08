// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const (
	ServiceTableName   = "k8s-services"
	EndpointsTableName = "k8s-endpoints"
)

var (
	// ServiceIDIndex is an index on the service's namespace and name.
	ServiceIDIndex = statedb.Index[*slim_corev1.Service, types.NamespacedName]{
		Name: "id",
		FromObject: func(s *slim_corev1.Service) index.KeySet {
			return index.NewKeySet(index.String(s.Namespace + "/" + s.Name))
		},
		FromKey: func(k types.NamespacedName) index.Key {
			return index.String(k.String())
		},
		Unique: true,
	}

	// EndpointsIDIndex is an index on the endpoints's namespace and name.
	EndpointsIDIndex = statedb.Index[*k8s.Endpoints, types.NamespacedName]{
		Name: "id",
		FromObject: func(e *k8s.Endpoints) index.KeySet {
			return index.NewKeySet(index.String(e.Namespace + "/" + e.EndpointSliceName))
		},
		FromKey: func(k types.NamespacedName) index.Key {
			return index.String(k.String())
		},
		Unique: true,
	}

	// EndpointsByServiceIndex is an index on the service's namespace and name.
	EndpointsByServiceIndex = statedb.Index[*k8s.Endpoints, types.NamespacedName]{
		Name: "service-id",
		FromObject: func(e *k8s.Endpoints) index.KeySet {
			return index.NewKeySet(index.String(e.ServiceName.String()))
		},
		FromKey: func(k types.NamespacedName) index.Key {
			return index.String(k.String())
		},
		Unique: false,
	}
)

// SvcEPTablesCell provides the statedb tables for Kubernetes services and endpoints.
// These tables are populated directly from Kubernetes and are meant to replace the
// existing 'resource.Resource' based caches.
var SvcEPTablesCell = cell.Module(
	"k8s-svcep-tables",
	"statedb tables for Kubernetes Services and Endpoints",

	cell.Provide(
		NewServiceTable,
		NewEndpointsTable,
	),

	cell.Invoke(registerSvcEPReflector),
)

func NewServiceTable(db *statedb.DB) (statedb.RWTable[*slim_corev1.Service], error) {
	tbl, err := statedb.NewTable(
		ServiceTableName,
		ServiceIDIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func NewEndpointsTable(db *statedb.DB) (statedb.RWTable[*k8s.Endpoints], error) {
	tbl, err := statedb.NewTable(
		EndpointsTableName,
		EndpointsIDIndex,
		EndpointsByServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

type reflectorParams struct {
	cell.In

	Log       *slog.Logger
	DB        *statedb.DB
	Services  statedb.RWTable[*slim_corev1.Service]
	Endpoints statedb.RWTable[*k8s.Endpoints]
	JobGroup  job.Group
	Clientset client.Clientset
}

func registerSvcEPReflector(p reflectorParams) {
	if !p.Clientset.IsEnabled() {
		return
	}

	svcLW := utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](p.Clientset.Slim().CoreV1().Services(""))
	k8s.RegisterReflector(
		p.JobGroup,
		p.DB,
		k8s.ReflectorConfig[*slim_corev1.Service]{
			Name:          "k8s-services",
			Table:         p.Services,
			ListerWatcher: svcLW,
			MetricScope:   "Service",
		},
	)

	epSliceLW := utils.ListerWatcherFromTyped[*slim_discovery_v1.EndpointSliceList](p.Clientset.Slim().DiscoveryV1().EndpointSlices(""))
	k8s.RegisterReflector(
		p.JobGroup,
		p.DB,
		k8s.ReflectorConfig[*k8s.Endpoints]{
			Name:          "k8s-endpoints",
			Table:         p.Endpoints,
			ListerWatcher: epSliceLW,
			MetricScope:   "EndpointSlice",
			Transform: func(_ statedb.ReadTxn, obj any) (*k8s.Endpoints, bool) {
				ep, ok := obj.(*slim_discovery_v1.EndpointSlice)
				if !ok {
					p.Log.Warn("svcep_tables: unexpected object type", "object", obj)
					return nil, false
				}
				return k8s.ParseEndpointSliceV1(p.Log, ep), true
			},
		},
	)
}
