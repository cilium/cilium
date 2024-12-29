// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/u8proto"
)

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	// UpdateRules synchronously updates the rules for the given proxy redirect.
	// Note: UpdateRules is not called when a redirect is created.
	UpdateRules(rules policy.L7DataMap) (revert.RevertFunc, error)

	// Close closes and cleans up resources associated with the redirect
	// implementation. The implementation should .Add to the WaitGroup if the
	// update is asynchronous and the update should not return until it is
	// complete.
	Close()
}

type Redirect struct {
	// The following fields are only written to during initialization, it
	// is safe to read these fields without locking the mutex
	name           string
	proxyPort      *proxyports.ProxyPort
	dstPortProto   restore.PortProto
	endpointID     uint16
	implementation RedirectImplementation
}

func newRedirect(epID uint16, name string, listener *proxyports.ProxyPort, port uint16, proto u8proto.U8proto) *Redirect {
	return &Redirect{
		name:         name,
		proxyPort:    listener,
		dstPortProto: restore.MakeV2PortProto(port, proto),
		endpointID:   epID,
	}
}
