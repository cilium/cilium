// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgp/types"
)

type FakeRouterProvider struct{}

func NewFakeRouterProvider() types.RouterProvider {
	return &FakeRouterProvider{}
}

func (p *FakeRouterProvider) NewRouter(ctx context.Context, logger *slog.Logger, params types.ServerParameters) (types.Router, error) {
	return NewFakeRouter(), nil
}
