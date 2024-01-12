package main

import (
	"encoding/json"
	"net/http"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/sirupsen/logrus"
)

func registerHTTPServer(
	lc hive.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB,
	mux *http.ServeMux,
	health cell.Health) {

	// For dumping the database:
	// curl -s localhost:8080/statedb | jq .
	mux.Handle("/statedb", db)

	healthHandler := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		b, err := json.Marshal(health.All())
		if err != nil {
			w.WriteHeader(500)
		} else {
			w.WriteHeader(200)
			w.Write(b)
		}
	}
	// For dumping module health status:
	// curl -s localhost:8080/health | jq
	mux.HandleFunc("/health", healthHandler)

	server := http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			log.Infof("Serving API at %s", server.Addr)
			go server.ListenAndServe()
			return nil
		},
		OnStop: func(ctx hive.HookContext) error {
			return server.Shutdown(ctx)
		},
	})

}
