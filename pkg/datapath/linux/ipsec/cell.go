// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// The IPsec agent handles key-related initialisation tasks for the ipsec subsystem.
var Cell = cell.Module(
	"ipsec-agent",
	"Handles initial key setup and knows the key size",

	cell.Provide(newIPsecAgent),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle

	Log            *slog.Logger
	JobGroup       job.Group
	LocalNodeStore *node.LocalNodeStore
	Config         *option.DaemonConfig
	EncryptMap     encrypt.EncryptMap
}

// newIPsecAgent returns the [*Agent] as an interface [types.IPsecAgent].
func newIPsecAgent(p params) types.IPsecAgent {
	return newAgent(p.Lifecycle, p.Log, p.JobGroup, p.LocalNodeStore, p.Config, p.EncryptMap)
}
