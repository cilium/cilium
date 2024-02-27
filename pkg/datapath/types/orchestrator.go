// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
)

type Orchestrator interface {
	Reinitialize(ctx context.Context, owner BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr IptablesManager, p Proxy) error
}
