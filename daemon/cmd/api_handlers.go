// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type handlersOut struct {
	cell.Out

	DaemonGetDebuginfoHandler daemon.GetDebuginfoHandler
}

// apiHandler implements Handle() for the given parameter type.
// It allows expressing the API handlers requiring *Daemon as simply
// as a function of form `func(d *Daemon, p ParamType) middleware.Responder`.
// This wrapper takes care of Await'ing for *Daemon.
type apiHandler[Params any] struct {
	dp      promise.Promise[*Daemon]
	handler func(d *Daemon, p Params) middleware.Responder
}

func (a *apiHandler[Params]) Handle(p Params) middleware.Responder {
	// Wait for *Daemon to be ready. While 'p' would have a context, it's hard to get it
	// since it's a struct. Could use reflection, but since we'll stop the agent anyway
	// if daemon initialization fails it doesn't really matter that much here what context
	// to use.
	d, err := a.dp.Await(context.Background())
	if err != nil {
		return api.Error(http.StatusServiceUnavailable, err)
	}
	return a.handler(d, p)
}

func wrapAPIHandler[Params any](dp promise.Promise[*Daemon], handler func(d *Daemon, p Params) middleware.Responder) *apiHandler[Params] {
	return &apiHandler[Params]{dp: dp, handler: handler}
}

// apiHandlers bridges the API handlers still implemented inside Daemon into a set of
// individual handlers. Since NewDaemon() is side-effectful, we can only get a promise for
// *Daemon, and thus the handlers will need to Await() for it to be ready.
func ciliumAPIHandlers(dp promise.Promise[*Daemon], cfg *option.DaemonConfig) (out handlersOut) {
	// /debuginfo
	out.DaemonGetDebuginfoHandler = wrapAPIHandler(dp, getDebugInfoHandler)

	return
}
