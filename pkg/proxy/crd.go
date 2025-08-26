// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// Redirect type for custom Listeners, which are managed externally.
type CRDRedirect struct {
	Redirect
}

func (dr *CRDRedirect) GetRedirect() *Redirect {
	return &dr.Redirect
}

func (r *CRDRedirect) UpdateRules(rules policy.L7DataMap) (revert.RevertFunc, error) {
	return nil, nil
}

func (r *CRDRedirect) Close() {
}
