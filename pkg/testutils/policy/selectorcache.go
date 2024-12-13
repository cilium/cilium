// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testpolicy

import (
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/types"
)

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector types.CachedSelector, added, deleted []identity.NumericIdentity) {
}

func (d *DummySelectorCacheUser) IdentitySelectionCommit(*versioned.Tx) {
}

func (d *DummySelectorCacheUser) IsPeerSelector() bool {
	return true
}
