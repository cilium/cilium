package servicemanager

import (
	datapathlb "github.com/cilium/cilium/pkg/datapath/lb"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"service-manager",
	"Manages the load-balancing frontends and backends",

	cell.Provide(New),
	cell.Invoke(func(ServiceManager) {}), // force for now.
)

type params struct {
	cell.In

	DPLB datapathlb.LoadBalancer
}
