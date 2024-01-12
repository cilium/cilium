package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"path"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

var handlersCell = cell.Invoke(registerHandlers)

func registerHandlers(mux *http.ServeMux, db *statedb.DB, svcs statedb.RWTable[*Service], eps statedb.RWTable[*Endpoint]) {
	mux.HandleFunc("/services", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var svc *Service
		body, err := io.ReadAll(req.Body)
		if err == nil {
			err = json.Unmarshal(body, &svc)
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		svc.Source = SourceAPI

		txn := db.WriteTxn(svcs)
		svcs.Insert(txn, svc)
		txn.Commit()
	})

	mux.HandleFunc("/services/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		name := path.Base(req.URL.Path)
		txn := db.WriteTxn(svcs)
		svcs.Delete(txn, &Service{Name: name})
		txn.Commit()
	})

	mux.HandleFunc("/endpoints", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var ep *Endpoint
		body, err := io.ReadAll(req.Body)
		if err == nil {
			err = json.Unmarshal(body, &ep)
		}
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte(err.Error()))
			return
		}
		ep.Source = SourceAPI
		txn := db.WriteTxn(eps)
		eps.Insert(txn, ep)
		txn.Commit()
	})

	mux.HandleFunc("/endpoints/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		name := path.Base(req.URL.Path)
		txn := db.WriteTxn(eps)
		eps.Delete(txn, &Endpoint{Service: name})
		txn.Commit()
	})

}
