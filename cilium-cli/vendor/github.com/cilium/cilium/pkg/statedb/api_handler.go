// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/statedb"
	"github.com/cilium/cilium/pkg/api"
)

func newDumpHandler(db *DB) restapi.GetStatedbDumpHandler {
	return &dumpHandler{db}
}

// REST API handler for the '/statedb/dump' to dump the contents of the database
// as JSON. Available through `cilium statedb dump` and included in sysdumps.
type dumpHandler struct {
	db *DB
}

func (h *dumpHandler) Handle(params restapi.GetStatedbDumpParams) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		h.db.ReadTxn().WriteJSON(w)
	})
}

// REST API handler for '/statedb/query' to perform remote Get() and LowerBound()
// queries against the database from 'cilium-dbg'.
func newQueryHandler(db *DB) restapi.GetStatedbQueryTableHandler {
	return &queryHandler{db}
}

type queryHandler struct {
	db *DB
}

// /statedb/query
func (h *queryHandler) Handle(params restapi.GetStatedbQueryTableParams) middleware.Responder {
	queryKey, err := base64.StdEncoding.DecodeString(params.Key)
	if err != nil {
		return api.Error(restapi.GetStatedbQueryTableBadRequestCode, fmt.Errorf("Invalid key: %w", err))
	}

	txn := h.db.ReadTxn()
	indexTxn, err := txn.getTxn().indexReadTxn(params.Table, params.Index)
	if err != nil {
		return api.Error(restapi.GetStatedbQueryTableNotFoundCode, err)
	}

	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		w.WriteHeader(restapi.GetStatedbDumpOKCode)
		enc := gob.NewEncoder(w)
		onObject := func(obj object) error {
			if err := enc.Encode(obj.revision); err != nil {
				return err
			}
			return enc.Encode(obj.data)
		}
		runQuery(indexTxn, params.Lowerbound, queryKey, onObject)
	})
}

func runQuery(indexTxn indexTxn, lowerbound bool, queryKey []byte, onObject func(object) error) {
	iter := indexTxn.Root().Iterator()
	if lowerbound {
		iter.SeekLowerBound(queryKey)
	} else {
		iter.SeekPrefixWatch(queryKey)
	}
	var match func([]byte) bool
	switch {
	case lowerbound:
		match = func([]byte) bool { return true }
	case indexTxn.entry.unique:
		match = func(k []byte) bool { return len(k) == len(queryKey) }
	default:
		match = func(k []byte) bool {
			_, secondary := decodeNonUniqueKey(k)
			return len(secondary) == len(queryKey)
		}
	}
	for key, obj, ok := iter.Next(); ok; _, obj, ok = iter.Next() {
		if !match(key) {
			continue
		}
		if err := onObject(obj); err != nil {
			return
		}
	}
}
