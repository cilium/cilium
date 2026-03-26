// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"encryptmap",
	"IPsec encrypt map",
	cell.Provide(newEncryptMap),
)

// newEncryptMap returns the [*encryptMap] as an interface [EncryptMap].
func newEncryptMap(lc cell.Lifecycle, ipsecCfg ipsec.Config, dc *option.DaemonConfig) bpf.MapOut[EncryptMap] {
	return bpf.NewMapOut(EncryptMap(newMap(lc, ipsecCfg, dc)))
}
