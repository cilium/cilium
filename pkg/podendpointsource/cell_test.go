// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

// TestCell verifies that the cell can be populated with a minimal set of
// external dependencies. The lifecycle hook (AddListener,
// WaitForInitialGlobalIdentities) is not exercised here; it runs only when
// the hive is Start()-ed. Populate is enough to catch wiring regressions.
func TestCell(t *testing.T) {
	logger := hivetest.Logger(t)

	err := hive.New(
		Cell,
		cell.Provide(
			func() identityCache.IdentityAllocator {
				return testidentity.NewMockIdentityAllocator(nil)
			},
			func() *ipcache.IPCache {
				return ipcache.NewIPCache(&ipcache.Configuration{
					Context:           t.Context(),
					Logger:            logger,
					IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
					IdentityUpdater:   &noopIdentityUpdater{},
				})
			},
		),
	).Populate(logger)
	if err != nil {
		t.Fatal(err)
	}
}

// noopIdentityUpdater satisfies the ipcachetypes.IdentityUpdater contract
// required by the IPCache constructor without performing any work.
type noopIdentityUpdater struct{}

func (*noopIdentityUpdater) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
