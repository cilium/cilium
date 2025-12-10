// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testpolicy

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/types"
)

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(logger *slog.Logger, selector types.CachedSelector, added, deleted []identity.NumericIdentity) {
}

func (d *DummySelectorCacheUser) IdentitySelectionCommit(logger *slog.Logger, txn *versioned.Tx) {
}

func (d *DummySelectorCacheUser) IsPeerSelector() bool {
	return true
}
