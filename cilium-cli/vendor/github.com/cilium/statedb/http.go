// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cilium/statedb/part"
)

func (db *DB) HTTPHandler() http.Handler {
	h := dbHandler{db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dump", h.dumpAll)
	mux.HandleFunc("GET /dump/{table}", h.dumpTable)
	mux.HandleFunc("GET /query", h.query)
	return mux
}

type dbHandler struct {
	db *DB
}

func (h dbHandler) dumpAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	h.db.ReadTxn().WriteJSON(w)
}

func (h dbHandler) dumpTable(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	var err error
	if table := r.PathValue("table"); table != "" {
		err = h.db.ReadTxn().WriteJSON(w, r.PathValue("table"))
	} else {
		err = h.db.ReadTxn().WriteJSON(w)
	}
	if err != nil {
		panic(err)
	}
}

func (h dbHandler) query(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)

	var req QueryRequest
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(QueryResponse{Err: err.Error()})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(QueryResponse{Err: err.Error()})
		return
	}

	queryKey, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(QueryResponse{Err: err.Error()})
		return
	}

	txn := h.db.ReadTxn().getTxn()

	// Look up the table
	var table TableMeta
	for _, e := range txn.root {
		if e.meta.Name() == req.Table {
			table = e.meta
		}
	}
	if table == nil {
		w.WriteHeader(http.StatusNotFound)
		enc.Encode(QueryResponse{Err: fmt.Sprintf("Table %q not found", req.Table)})
		return
	}

	indexPos := table.indexPos(req.Index)

	indexTxn, err := txn.indexReadTxn(table, indexPos)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(QueryResponse{Err: err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	onObject := func(obj object) error {
		return enc.Encode(QueryResponse{
			Rev: obj.revision,
			Obj: obj.data,
		})
	}
	runQuery(indexTxn, req.LowerBound, queryKey, onObject)
}

type QueryRequest struct {
	Key        string `json:"key"` // Base64 encoded query key
	Table      string `json:"table"`
	Index      string `json:"index"`
	LowerBound bool   `json:"lowerbound"`
}

type QueryResponse struct {
	Rev uint64 `json:"rev"`
	Obj any    `json:"obj"`
	Err string `json:"err,omitempty"`
}

func runQuery(indexTxn indexReadTxn, lowerbound bool, queryKey []byte, onObject func(object) error) {
	var iter *part.Iterator[object]
	if lowerbound {
		iter = indexTxn.LowerBound(queryKey)
	} else {
		iter, _ = indexTxn.Prefix(queryKey)
	}
	var match func([]byte) bool
	switch {
	case lowerbound:
		match = func([]byte) bool { return true }
	case indexTxn.unique:
		match = func(k []byte) bool { return len(k) == len(queryKey) }
	default:
		match = func(k []byte) bool {
			_, secondary := decodeNonUniqueKey(k)
			return len(secondary) == len(queryKey)
		}
	}
	for key, obj, ok := iter.Next(); ok; key, obj, ok = iter.Next() {
		if !match(key) {
			continue
		}
		if err := onObject(obj); err != nil {
			panic(err)
		}
	}
}
