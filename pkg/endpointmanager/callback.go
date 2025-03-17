// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"sync"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
)

var _ PolicyUpdateCallbackManager = (*endpointManager)(nil)

// CallBackFunc is the call back function type for policy updates.
// Regenerated IDs are passed to the function, if this set is empty, the caller
// needs to perform the actions for all endpoint policies.
type CallBackFunc func(idsRegen *set.Set[identity.NumericIdentity], incremental bool) error

type policyUpdateCallbackDetails struct {
	cbMutex lock.RWMutex

	// policyUpdateCallbackFuncs is the map of endpoint policy callback update functions
	// mutex must be held to read and write.
	policyUpdateCallbackFuncs map[string]CallBackFunc
}

func newPolicyUpdateCallbackDetails() policyUpdateCallbackDetails {
	return policyUpdateCallbackDetails{
		policyUpdateCallbackFuncs: make(map[string]CallBackFunc),
	}
}

type PolicyUpdateCallbackManager interface {
	// RegisterPolicyUpdateCallback registers the callback for policy update
	RegisterPolicyUpdateCallback(name string, cb CallBackFunc)
	// DeregisterPolicyUpdateCallback removes the callback for policy update
	DeregisterPolicyUpdateCallback(name string)
}

// RegisterPolicyUpdateCallback is to satisfy the PolicyUpdateCallbackManager interface.
func (mgr *endpointManager) RegisterPolicyUpdateCallback(name string, updateFunc CallBackFunc) {
	mgr.cbMutex.Lock()
	defer mgr.cbMutex.Unlock()

	mgr.policyUpdateCallbackFuncs[name] = updateFunc
}

// DeregisterPolicyUpdateCallback is to satisfy the PolicyUpdateCallbackManager interface.
func (mgr *endpointManager) DeregisterPolicyUpdateCallback(name string) {
	mgr.cbMutex.Lock()
	defer mgr.cbMutex.Unlock()
	delete(mgr.policyUpdateCallbackFuncs, name)
}

// policyUpdateCallback perform the call back in separate goroutines.
// This is non-blocking and returns immediately, the caller can wait
// for completion by using the wait group if required.
func (mgr *endpointManager) policyUpdateCallback(wg *sync.WaitGroup, idsToRegen *set.Set[identity.NumericIdentity], incremental bool) {
	mgr.cbMutex.RLock()
	defer mgr.cbMutex.RUnlock()
	wg.Add(len(mgr.policyUpdateCallbackFuncs))

	for _, fn := range mgr.policyUpdateCallbackFuncs {
		go func(f CallBackFunc) {
			_ = f(idsToRegen, incremental)
			wg.Done()
		}(fn)
	}
}
