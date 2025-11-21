// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgp/types"
)

// RouterProvider provides GoBGP server instances.
type RouterProvider struct{}

func NewRouterProvider() types.RouterProvider {
	return &RouterProvider{}
}

func (p *RouterProvider) NewRouter(ctx context.Context, log *slog.Logger, params types.ServerParameters) (types.Router, error) {
	return NewGoBGPServer(ctx, log, params)
}
