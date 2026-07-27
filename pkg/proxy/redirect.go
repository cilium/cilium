// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/u8proto"
)

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	// GetRedirect returns the static config of the redirect
	GetRedirect() *Redirect

	// UpdateRules synchronously updates the rules for the given proxy redirect.
	// Note: UpdateRules is not called when a redirect is created.
	UpdateRules(rules policy.L7DataMap) (revert.RevertFunc, error)

	// Close closes and cleans up resources associated with the redirect
	// implementation. The implementation should .Add to the WaitGroup if the
	// update is asynchronous and the update should not return until it is
	// complete.
	Close()
}

// Redirect is the common static config for each RedirectImplementation
type Redirect struct {
	logger       *slog.Logger
	name         string
	proxyPort    *proxyports.ProxyPort
	dstPortProto restore.PortProto
	endpointID   uint16
}

func initRedirect(logger *slog.Logger, epID uint16, name string, listener *proxyports.ProxyPort, port uint16, proto u8proto.U8proto) Redirect {
	return Redirect{
		logger:       logger,
		name:         name,
		proxyPort:    listener,
		dstPortProto: restore.MakeV2PortProto(port, proto),
		endpointID:   epID,
	}
}
