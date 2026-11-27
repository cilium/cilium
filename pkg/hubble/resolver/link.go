// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"strconv"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
)

// LinkGetter implements types.LinkGetter using the devices table.
type LinkGetter struct {
	db      *statedb.DB
	devices statedb.Table[*tables.Device]
}

func NewLinkGetter(db *statedb.DB, devices statedb.Table[*tables.Device]) types.LinkGetter {
	return &LinkGetter{db: db, devices: devices}
}

// GetIfNameCached implements types.LinkGetter.
func (g *LinkGetter) GetIfNameCached(ifIndex int) (string, bool) {
	dev, _, found := g.devices.Get(g.db.ReadTxn(), tables.DeviceByIndex(ifIndex))
	// A device seen only through address or route updates has no name yet.
	if !found || dev.Name == "" {
		return "", false
	}
	return dev.Name, true
}

// Name implements types.LinkGetter.
func (g *LinkGetter) Name(ifIndex uint32) string {
	if name, ok := g.GetIfNameCached(int(ifIndex)); ok {
		return name
	}
	return strconv.FormatUint(uint64(ifIndex), 10)
}
