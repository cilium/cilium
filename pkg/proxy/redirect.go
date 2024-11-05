// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/u8proto"
)

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	// UpdateRules updates the rules for the given proxy redirect.
	// The implementation should .Add to the WaitGroup if the update is
	// asynchronous and the update should not return until it is complete.
	// The returned RevertFunc must be non-nil.
	// Note: UpdateRules is not called when a redirect is created.
	UpdateRules(wg *completion.WaitGroup) (revert.RevertFunc, error)

	// Close closes and cleans up resources associated with the redirect
	// implementation. The implementation should .Add to the WaitGroup if the
	// update is asynchronous and the update should not return until it is
	// complete.
	Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc)
}

type Redirect struct {
	// The following fields are only written to during initialization, it
	// is safe to read these fields without locking the mutex
	name           string
	listener       *ProxyPort
	dstPortProto   restore.PortProto
	endpointID     uint64
	localEndpoint  endpoint.EndpointUpdater
	implementation RedirectImplementation

	// The following fields are updated while the redirect is alive, the
	// mutex must be held to read and write these fields
	mutex lock.RWMutex
	rules policy.L7DataMap
}

func newRedirect(localEndpoint endpoint.EndpointUpdater, name string, listener *ProxyPort, port uint16, proto u8proto.U8proto) *Redirect {
	return &Redirect{
		name:          name,
		listener:      listener,
		dstPortProto:  restore.MakeV2PortProto(port, proto),
		endpointID:    localEndpoint.GetID(),
		localEndpoint: localEndpoint,
	}
}

// updateRules updates the rules of the redirect, Redirect.mutex must be held
// 'implementation' is not initialized when this is called the first time.
// TODO: Replace this with RedirectImplementation UpdateRules method!
func (r *Redirect) updateRules(p policy.ProxyPolicy) revert.RevertFunc {
	oldRules := r.rules
	r.rules = p.CopyL7RulesPerEndpoint()
	return func() error {
		r.mutex.Lock()
		r.rules = oldRules
		r.mutex.Unlock()
		return nil
	}
}
