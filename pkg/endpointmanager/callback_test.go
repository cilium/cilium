// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
)

const numberOfEndpointPolicies = 10

func Test_PolicyUpdateCallback(t *testing.T) {
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	called := int32(0)
	updateFunc := func(idsRegen *set.Set[identity.NumericIdentity], incremental bool) error {
		atomic.AddInt32(&called, 1)
		return nil
	}

	for i := range numberOfEndpointPolicies {
		mgr.RegisterPolicyUpdateCallback(fmt.Sprintf("callback-%d", i), updateFunc)
	}
	wg := sync.WaitGroup{}
	mgr.policyUpdateCallback(&wg, nil, false)
	wg.Wait()
	require.Equal(t, int32(10), called)

	for i := range numberOfEndpointPolicies {
		mgr.DeregisterPolicyUpdateCallback(fmt.Sprintf("callback-%d", i))
	}
	wg = sync.WaitGroup{}
	mgr.policyUpdateCallback(&wg, nil, false)
	wg.Wait()
	require.Equal(t, int32(10), called)
}
