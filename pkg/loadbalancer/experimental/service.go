// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

// Service defines the common properties for a load-balancing service. Associated with a
// service are a set of frontends that receive the traffic, and a set of backends to which
// the traffic is directed. A single frontend can map to a partial subset of backends depending
// on its properties.
type Service struct {
	Name   loadbalancer.ServiceName // Fully qualified service name
	Source source.Source            // Data source
	Labels labels.Labels

	// NOTE: Many fields we require later one were omitted for simplicity
	// as we experiment with this.
}

func (svc *Service) Clone() *Service {
	svc2 := *svc
	return &svc2
}

func (svc *Service) TableHeader() []string {
	return []string{
		"Name",
		"Source",
		"Labels",
	}
}

func (svc *Service) TableRow() []string {
	return []string{
		svc.Name.String(),
		string(svc.Source),
		svc.Labels.String(),
	}
}

var (
	ServiceNameIndex = statedb.Index[*Service, loadbalancer.ServiceName]{
		Name: "name",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(index.Stringer(obj.Name))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  true,
	}
)

const (
	ServiceTableName = "services"
)

func NewServicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	tbl, err := statedb.NewTable(
		ServiceTableName,
		ServiceNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
