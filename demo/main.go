package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/cilium/cilium/demo/controlplane"
	"github.com/cilium/cilium/demo/datapath"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Hive = hive.New(Demo)

	cmd = &cobra.Command{
		Use: "example",
		Run: func(_ *cobra.Command, args []string) {
			if err := Hive.Run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func main() {
	Hive.RegisterFlags(cmd.Flags())
	cmd.AddCommand(Hive.Command())
	cmd.Execute()
}

var Demo = cell.Module(
	"demo",
	"Demo for statedb and reconcilers",

	client.Cell, // client.Clientset for accessing K8s
	cell.Invoke(func(cs client.Clientset) error {
		if !cs.IsEnabled() {
			return errors.New("Please provide --k8s-kubeconfig-path")
		}
		return nil
	}),

	// Serve metrics over localhost:9962/metrics.
	cell.Group(
		// TODO: Clean up use of modular metrics outside the agent.
		cell.ProvidePrivate(func() *option.DaemonConfig {
			return option.Config
		}),
		cell.Config(metrics.RegistryConfig{PrometheusServeAddr: ":9962"}),
		cell.Provide(metrics.NewRegistry),
		cell.Invoke(func(*metrics.Registry) {}),
	),
	statedb.Cell,    // statedb.DB
	job.Cell,        // job.Registry for background jobs
	reconciler.Cell, // the shared reconciler metrics

	// Control-plane of the demo application pulls Service and Endpoints objects
	// from the Kubernetes API server and compute from it the desired datapath state for
	// frontends and backends.
	controlplane.Cell,

	// Datapath for the demo defines the models and tables for the desired state,
	// BPF maps (frontends and backends) and instantiates reconcilers to reconcile
	// the desired state tables to the BPF maps.
	datapath.Cell,

	cell.Invoke(registerHTTPServer),
)

func registerHTTPServer(
	lc hive.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB,
	health cell.Health) {

	mux := http.NewServeMux()

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
