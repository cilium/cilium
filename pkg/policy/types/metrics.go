// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/policy/api"

type PolicyMetrics interface {
	AddRule(r api.Rule)
	DelRule(r api.Rule)
}
