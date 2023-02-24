// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

func getNodeIDHandlerHandler(d *Daemon, _ GetNodeIdsParams) middleware.Responder {
	dump := d.datapath.NodeIDs().DumpNodeIDs()
	return NewGetNodeIdsOK().WithPayload(dump)
}
