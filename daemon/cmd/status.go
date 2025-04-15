// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

func getHealthzHandler(d *Daemon, params GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	requireK8sConnectivity := params.RequireK8sConnectivity != nil && *params.RequireK8sConnectivity
	sr := d.statusCollector.GetStatus(brief, requireK8sConnectivity)
	return NewGetHealthzOK().WithPayload(&sr)
}
