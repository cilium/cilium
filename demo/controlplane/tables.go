package controlplane

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var tablesCell = cell.Module(
	"controlplane-tables",
	"Demo control-plane tables",

	cell.Provide(
		servicesTable,
		statedb.RWTable[*Service].ToTable,

		endpointsTable,
		statedb.RWTable[*Endpoint].ToTable,
	),
)

var (
	ServicesNameIndex = statedb.Index[*Service, string]{
		Name: "name",
		FromObject: func(s *Service) index.KeySet {
			return index.NewKeySet(index.String(s.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	ServicesSourceIndex = statedb.Index[*Service, Source]{
		Name: "source",
		FromObject: func(s *Service) index.KeySet {
			return index.NewKeySet(index.String(string(s.Source)))
		},
		FromKey: func(s Source) index.Key { return index.String(string(s)) },
		Unique:  false,
	}
)

func servicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	table, err := statedb.NewTable[*Service]("services", ServicesNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}

var (
	EndpointsNameIndex = statedb.Index[*Endpoint, string]{
		Name: "name",
		FromObject: func(b *Endpoint) index.KeySet {
			return index.NewKeySet(index.String(b.Service))
		},
		FromKey: index.String,
		Unique:  true,
	}

	EndpointsSourceIndex = statedb.Index[*Endpoint, Source]{
		Name: "source",
		FromObject: func(s *Endpoint) index.KeySet {
			return index.NewKeySet(index.String(string(s.Source)))
		},
		FromKey: func(s Source) index.Key { return index.String(string(s)) },
		Unique:  false,
	}
)

func endpointsTable(db *statedb.DB) (statedb.RWTable[*Endpoint], error) {
	table, err := statedb.NewTable[*Endpoint]("endpoints", EndpointsNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}
