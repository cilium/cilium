// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/server/restapi/statedb"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/statedb"
)

func newDumpHandler(db *DB) restapi.GetStatedbDumpHandler {
	return &dumphandler{db}
}

// REST API handler for the StateDB, handles JSON Dumping. The dump is also
// available through `cilium statedb dump`, and is included in sysdumps.
type dumphandler struct {
	db *DB
}

// /statedb/dump
func (h *dumphandler) Handle(params GetStatedbDumpParams) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		h.db.ReadTxn().WriteJSON(w)
	})
}
