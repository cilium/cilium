package main

import (
	"log"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/daemon/tables"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

var svcs *tables.Services

var Hive = hive.New(
	job.Cell,
	client.Cell,
	statedb.Cell,
	reconciler.Cell,

	tables.ServicesCell,
	tables.K8sReflectorCell,

	cell.Invoke(httpServer),

	/*
		cell.Invoke(func(s *tables.Services) {
			go demo(s)
		}),*/
)

var cmd = &cobra.Command{
	Use: "example",
	Run: func(_ *cobra.Command, args []string) {
		if err := Hive.Run(); err != nil {
			log.Fatal(err)
		}
	},
}

func main() {
	// Register all configuration flags in the hive to the command
	Hive.RegisterFlags(cmd.Flags())

	// Add the "hive" sub-command for inspecting the hive
	cmd.AddCommand(Hive.Command())

	// And finally execute the command to parse the command-line flags and
	// run the hive
	cmd.Execute()
}

func demo(s *tables.Services) {
	name := loadbalancer.ServiceName{
		Namespace: "foo",
		Name:      "bar",
	}

	txn := s.WriteTxn()
	s.UpsertService(
		txn,
		name,
		&tables.ServiceParams{
			L3n4Addr:        *loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster("1.2.3.4"), 12345, loadbalancer.ScopeExternal),
			Type:            loadbalancer.SVCTypeClusterIP,
			Labels:          map[string]labels.Label{},
			Source:          source.Kubernetes,
			NatPolicy:       loadbalancer.SVCNatPolicyNone,
			ExtPolicy:       loadbalancer.SVCTrafficPolicyNone,
			IntPolicy:       loadbalancer.SVCTrafficPolicyNone,
			SessionAffinity: nil,
			HealthCheck:     nil,
		},
	)
	s.UpsertService(
		txn,
		name,
		&tables.ServiceParams{
			L3n4Addr:        *loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster("0.0.0.0"), 40404, loadbalancer.ScopeExternal),
			Type:            loadbalancer.SVCTypeNodePort,
			Labels:          map[string]labels.Label{},
			Source:          source.Kubernetes,
			NatPolicy:       loadbalancer.SVCNatPolicyNone,
			ExtPolicy:       loadbalancer.SVCTrafficPolicyNone,
			IntPolicy:       loadbalancer.SVCTrafficPolicyNone,
			SessionAffinity: nil,
			HealthCheck:     nil,
		},
	)
	backend1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster("4.3.2.1"), 54321, loadbalancer.ScopeExternal)
	s.UpsertBackends(
		txn,
		name,
		tables.BackendParams{
			Source: source.Kubernetes,
			Backend: loadbalancer.Backend{
				L3n4Addr:   backend1,
				FEPortName: "foo",
				NodeName:   "bar",
				Weight:     123,
				State:      loadbalancer.BackendStateActive,
			},
		},
	)
	backend2 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster("4.3.2.2"), 54322, loadbalancer.ScopeExternal)
	s.UpsertBackends(
		txn,
		name,
		tables.BackendParams{
			Source: source.Kubernetes,
			Backend: loadbalancer.Backend{
				L3n4Addr:   backend2,
				FEPortName: "foo",
				NodeName:   "bar",
				Weight:     123,
				State:      loadbalancer.BackendStateTerminating,
			},
		},
	)
	txn.Commit()

	time.Sleep(time.Second)

	txn = s.WriteTxn()
	err := s.DeleteBackend(txn, name, backend1)
	if err != nil {
		panic(err)
	}
	txn.Commit()
}

func httpServer(
	lc cell.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB) {

	mux := http.NewServeMux()

	// For dumping the database:
	// curl -s http://localhost:8080/statedb | jq .
	mux.HandleFunc("/statedb", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		db.ReadTxn().WriteJSON(w)
	})

	server := http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			log.Infof("Serving API at %s", server.Addr)
			go server.ListenAndServe()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			return server.Shutdown(ctx)
		},
	})
}
