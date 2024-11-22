// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

func (m Metrics) AddLRPConfig(_ *redirectpolicy.LRPConfig) {
	m.NPLRPIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelLRPConfig(_ *redirectpolicy.LRPConfig) {
	m.NPLRPIngested.WithLabelValues(actionDel).Inc()
}
