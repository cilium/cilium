// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// Encryption returns a [BPFNetwork].
func Encryption(lnc *datapath.LocalNodeConfiguration) any {
	cfg := NewBPFNetwork(NodeConfig(lnc))

	return cfg
}
