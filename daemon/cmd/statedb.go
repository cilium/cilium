// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/server/restapi/statedb"
	"github.com/cilium/cilium/pkg/statedb"
)

type getStateDBDump struct {
	db statedb.DB
}

func (h *getStateDBDump) Handle(params GetStatedbDumpParams) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		h.db.WriteJSON(w)
	})
}
