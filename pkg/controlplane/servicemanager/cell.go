package servicemanager

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"service-manager",
	"Manages the collection of services with backends and updates datapath",

	cell.Provide(New),
)

type serviceManagerParams struct {
	cell.In

	// lbmap?
	// ...
}
