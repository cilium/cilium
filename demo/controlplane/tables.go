package controlplane

import (
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reflector"
	v1 "k8s.io/api/core/v1"
)

var tablesCell = cell.Module(
	"controlplane-tables",
	"Demo control-plane tables",

	cell.ProvidePrivate(servicesTable, servicesConfig),
	cell.Provide(statedb.RWTable[*Service].ToTable), // Provide Table[*Service]
	reflector.KubernetesCell[*Service](),

	cell.ProvidePrivate(endpointsTable, endpointsConfig),
	cell.Provide(statedb.RWTable[*Endpoint].ToTable), // Provide Table[*Endpoint]
	reflector.KubernetesCell[*Endpoint](),
)

var ServicesNameIndex = statedb.Index[*Service, string]{
	Name: "name",
	FromObject: func(s *Service) index.KeySet {
		return index.NewKeySet(index.String(s.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func servicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	table, err := statedb.NewTable[*Service]("services", ServicesNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}

func servicesConfig(cs client.Clientset, t statedb.RWTable[*Service]) reflector.KubernetesConfig[*Service] {
	return reflector.KubernetesConfig[*Service]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.ServiceList](cs.CoreV1().Services("")),
		Table:          t,
		Transform:      parseService,
	}
}

var EndpointsNameIndex = statedb.Index[*Endpoint, string]{
	Name: "name",
	FromObject: func(b *Endpoint) index.KeySet {
		return index.NewKeySet(index.String(b.Service))
	},
	FromKey: index.String,
	Unique:  true,
}

func endpointsTable(db *statedb.DB) (statedb.RWTable[*Endpoint], error) {
	table, err := statedb.NewTable[*Endpoint]("endpoints", EndpointsNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}

func endpointsConfig(cs client.Clientset, t statedb.RWTable[*Endpoint]) reflector.KubernetesConfig[*Endpoint] {
	return reflector.KubernetesConfig[*Endpoint]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.EndpointsList](cs.CoreV1().Endpoints("")),
		Table:          t,
		Transform:      parseEndpoints,
	}
}
