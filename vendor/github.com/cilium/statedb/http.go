// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cilium/statedb/index"
)

func (db *DB) HTTPHandler() http.Handler {
	h := dbHandler{db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dump", h.dumpAll)
	mux.HandleFunc("GET /dump/{table}", h.dumpTable)
	mux.HandleFunc("GET /query", h.query)
	mux.HandleFunc("GET /changes/{table}", h.changes)
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

	txn := h.db.ReadTxn()

	// Look up the table
	var table TableMeta
	for _, e := range txn.root() {
		if e.meta.Name() == req.Table {
			table = e.meta
			break
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

func runQuery(reader tableIndexReader, lowerbound bool, queryKey index.Key, onObject func(object) error) {
	var iter tableIndexIterator
	if lowerbound {
		iter, _ = reader.lowerBound(queryKey)
	} else {
		iter, _ = reader.list(queryKey)
	}
	for _, obj := range iter.All {
		if err := onObject(obj); err != nil {
			panic(err)
		}
	}
}

func (h dbHandler) changes(w http.ResponseWriter, r *http.Request) {
	const keepaliveInterval = 30 * time.Second

	enc := json.NewEncoder(w)
	tableName := r.PathValue("table")

	// Look up the table
	var tableMeta TableMeta
	for _, e := range h.db.ReadTxn().root() {
		if e.meta.Name() == tableName {
			tableMeta = e.meta
			break
		}
	}
	if tableMeta == nil {
		w.WriteHeader(http.StatusNotFound)
		enc.Encode(QueryResponse{Err: fmt.Sprintf("Table %q not found", tableName)})
		return
	}

	// Register for changes.
	wtxn := h.db.WriteTxn(tableMeta)
	changeIter, err := tableMeta.anyChanges(wtxn)
	wtxn.Commit()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		changes, watch := changeIter.nextAny(h.db.ReadTxn())
		for change := range changes {
			err := enc.Encode(change)
			if err != nil {
				panic(err)
			}
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return

		case <-ticker.C:
			// Send an empty keep-alive
			enc.Encode(Change[any]{})

		case <-watch:
		}
	}
}
