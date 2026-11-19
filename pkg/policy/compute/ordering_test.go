// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
)

// Every committed policy reaches RequestedRevision, whatever the interleaving of
// imports, revisions bumped by other paths, failing computations, and identities
// coming and going. This relies on every bump outside the importer being
// followed by a recomputation of all identities, see BumpRevision.
func TestOrderingEveryPolicyReachesRequestedRevision(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	for seed := range uint64(20) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			g := &gate{failing: map[identity.NumericIdentity]bool{}}
			_, _, computer, idmgr, repo := fixtureWithRepo(t, func(r policy.PolicyRepository) policy.PolicyRepository {
				g.PolicyRepository = r
				return g
			})
			rng := rand.New(rand.NewPCG(seed, seed))
			var ids []*identity.Identity
			for _, nid := range []identity.NumericIdentity{1, 2, 10, 11, 12, 13} {
				ids = append(ids, computeFor(t, computer, idmgr, nid))
			}
			local := map[identity.NumericIdentity]bool{}
			for _, id := range ids {
				local[id.ID] = true
			}
			stops := map[identity.NumericIdentity]func(){}
			random := func() *identity.Identity { return ids[rng.IntN(len(ids))] }
			selected := func() set.Set[identity.NumericIdentity] {
				var sel set.Set[identity.NumericIdentity]
				for _, id := range ids {
					if rng.IntN(3) == 0 {
						sel.Insert(id.ID)
					}
				}
				return sel
			}
			outsideBump := func() uint64 {
				rev := repo.BumpRevision()
				_, err := computer.RecomputeIdentityPolicyForAllIdentities(rev)
				require.NoError(t, err)
				return rev
			}

			for range 40 {
				switch rng.IntN(5) {
				case 0, 1:
					// An import of a few updates, possibly with revisions
					// bumped by another path in between. Like the importer, it
					// advances from the last such bump.
					from := repo.GetRevision()
					var sel set.Set[identity.NumericIdentity]
					var to uint64
					for range 1 + rng.IntN(3) {
						if rng.IntN(3) == 0 {
							from = outsideBump()
						}
						to = repo.BumpRevision()
						sel.Merge(selected())
					}
					computer.UpdatePolicy(sel, from, to)
				case 2:
					outsideBump()
				case 3:
					id := random()
					if stop, ok := stops[id.ID]; ok {
						stop()
						delete(stops, id.ID)
					} else {
						stops[id.ID] = g.fail(id.ID)
					}
				case 4:
					id := random()
					if local[id.ID] {
						idmgr.Remove(id)
					} else {
						idmgr.Add(id)
					}
					local[id.ID] = !local[id.ID]
				}
				time.Sleep(time.Duration(rng.IntN(2000)) * time.Microsecond)
			}
			for _, stop := range stops {
				stop()
			}

			// Every bump above was followed by an import's UpdatePolicy or by a
			// recomputation of all identities, so the requested revision is the
			// repository's.
			want := repo.GetRevision()
			require.Equal(t, want, computer.RequestedRevision())
			for _, id := range ids {
				if !local[id.ID] {
					require.Never(t, func() bool {
						_, _, _, found := computer.GetIdentityPolicyByIdentity(id)
						return found
					}, 20*time.Millisecond, time.Millisecond, "removed identity %d has a committed policy", id.ID)
					continue
				}
				require.Eventually(t, func() bool {
					res, _, _, found := computer.GetIdentityPolicyByIdentity(id)
					return found && res.CurrentAtRevision >= want
				}, 5*time.Second, time.Millisecond, "identity %d is not current at %d", id.ID, want)
			}
		})
	}
}

// gate is a repository that fails the computations of chosen identities.
type gate struct {
	policy.PolicyRepository

	mu      lock.Mutex
	failing map[identity.NumericIdentity]bool
}

func (g *gate) ComputeSelectorPolicy(id *identity.Identity) (policy.SelectorPolicy, uint64, error) {
	g.mu.Lock()
	failing := g.failing[id.ID]
	g.mu.Unlock()
	if failing {
		time.Sleep(time.Millisecond)
		return nil, 0, errors.New("injected failure")
	}
	return g.PolicyRepository.ComputeSelectorPolicy(id)
}

// fail makes computations of id fail until stop is called.
func (g *gate) fail(id identity.NumericIdentity) (stop func()) {
	g.mu.Lock()
	g.failing[id] = true
	g.mu.Unlock()
	return sync.OnceFunc(func() {
		g.mu.Lock()
		delete(g.failing, id)
		g.mu.Unlock()
	})
}
