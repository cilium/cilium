// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type PolicyMetrics interface {
	AddRule(r PolicyEntry)
	DelRule(r PolicyEntry)
}
