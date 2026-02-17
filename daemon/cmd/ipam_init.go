// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type ipamInitializerParams struct {
	cell.In

	Logger              *slog.Logger
	DirectRoutingDevice datapathTables.DirectRoutingDevice
	DB                  *statedb.DB
	IPAM                *ipam.IPAM
}

type ipamInitializer struct {
	logger              *slog.Logger
	directRoutingDevice datapathTables.DirectRoutingDevice
	db                  *statedb.DB
	ipam                *ipam.IPAM
}

func newIPAMInitializer(params ipamInitializerParams) *ipamInitializer {
	return &ipamInitializer{
		logger:              params.Logger,
		directRoutingDevice: params.DirectRoutingDevice,
		db:                  params.DB,
		ipam:                params.IPAM,
	}
}

func (r *ipamInitializer) configureAndStartIPAM(ctx context.Context) {
	// If the device has been specified, the IPv4AllocPrefix and the
	// IPv6AllocPrefix were already allocated before the k8s.Init().
	//
	// If the device hasn't been specified, k8s.Init() allocated the
	// IPv4AllocPrefix and the IPv6AllocPrefix from k8s node annotations.
	//
	// If k8s.Init() failed to retrieve the IPv4AllocPrefix we can try to derive
	// it from an existing node_config.h file or from previous cilium_host
	// interfaces.
	//
	// Then, we will calculate the IPv4 or IPv6 alloc prefix based on the IPv6
	// or IPv4 alloc prefix, respectively, retrieved by k8s node annotations.
	if option.Config.IPv4Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv4Range)
		if err != nil {
			logging.Fatal(
				r.logger,
				"Invalid IPv4 allocation prefix",
				logfields.Error, err,
				logfields.V4Prefix, option.Config.IPv4Range,
			)
		}
		node.SetIPv4AllocRange(allocCIDR)
	}

	if option.Config.IPv6Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			logging.Fatal(
				r.logger,
				"Invalid IPv6 allocation prefix",
				logfields.Error, err,
				logfields.V6Prefix, option.Config.IPv6Range,
			)
		}

		node.SetIPv6NodeRange(allocCIDR)
	}

	device := ""
	drd, _ := r.directRoutingDevice.Get(ctx, r.db.ReadTxn())
	if drd != nil {
		device = drd.Name
	}
	if err := node.AutoComplete(r.logger, device); err != nil {
		logging.Fatal(r.logger, "Cannot autocomplete node addresses", logfields.Error, err)
	}

	// start
	r.logger.Info("Initializing node addressing")
	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	r.ipam.ConfigureAllocator()
}

func (r *ipamInitializer) RestoreFinished() {
	r.ipam.RestoreFinished()
}
