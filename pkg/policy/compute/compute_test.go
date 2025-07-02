// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func TestRecomputeIdentityPolicy(t *testing.T) {
	testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())
	db, table, computer := fixture(t)
	assert.NotNil(t, db)
	assert.NotNil(t, table)

	init, err := computer.RecomputeIdentityPolicy(&identity.Identity{ID: identity.NumericIdentity(4)}, 0)
	assert.NoError(t, err)
	<-init

	ch := make(chan struct{})
	var (
		wg     sync.WaitGroup
		result Result
	)
	wg.Add(1)
	once := sync.Once{}
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			var (
				found bool
				watch <-chan struct{}
			)
			res, _, watch, found := computer.GetIdentityPolicyByNumericIdentity(identity.NumericIdentity(1))
			if found {
				result = res
				return
			} else {
				fmt.Println("not found")
			}
			once.Do(func() { close(ch) })
			select {
			case <-ticker.C:
				fmt.Println("trying again")
			case <-watch:
			}
		}
	}()

	<-ch

	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, err := computer.RecomputeIdentityPolicy(&identity.Identity{ID: identity.NumericIdentity(1)}, 0)
		assert.NoError(t, err)
		<-ch
	}()

	wg.Wait()

	assert.Equal(t, identity.NumericIdentity(1), result.Identity)
}

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[Result], PolicyRecomputer) {
	t.Helper()

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())

	var (
		db       *statedb.DB
		table    statedb.RWTable[Result]
		computer PolicyRecomputer
	)

	h := hive.New(
		cell.Module("test", "test",
			cell.Invoke(
				func(t statedb.RWTable[Result], db_ *statedb.DB, c_ PolicyRecomputer) error {
					table = t
					db = db_
					computer = c_
					return nil
				},
			),

			cell.ProvidePrivate(func() (policy.PolicyRepository, stream.Observable[policy.PolicyCacheChange]) {
				return repo, repo.PolicyCacheObservable()
			}),
			cell.ProvidePrivate(func() identitymanager.IDManager { return idmgr }),

			cell.Provide(
				func(params Params) PolicyRecomputer {
					return NewIdentityPolicyComputer(params)
				},
			),
			cell.ProvidePrivate(NewPolicyComputationTable),
		),
	)

	if err := h.Start(logger, context.Background()); err != nil {
		t.Fatalf("failed to start hive: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(logger, context.Background()); err != nil {
			t.Fatalf("failed to stop hive: %v", err)
		}
	})

	assert.NotNil(t, db)
	assert.NotNil(t, table)
	assert.NotNil(t, computer)

	return db, table, computer
}
