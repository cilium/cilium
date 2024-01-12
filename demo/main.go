package main

import (
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
	"Demo app for statedb and reconcilers",

	client.Cell,     // client.Clientset for accessing K8s
	statedb.Cell,    // statedb.DB
	job.Cell,        // job.Registry for background jobs
	reconciler.Cell, // the shared reconciler metrics

	// Check that kubeconfig path is configured, if not
	// fail to start.
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

	// Control-plane of the demo application pulls Service and Endpoints objects
	// from the Kubernetes API server and compute from it the desired datapath state for
	// frontends and backends.
	controlplane.Cell,

	// Datapath for the demo defines the models and tables for the desired state,
	// BPF maps (frontends and backends) and instantiates reconcilers to reconcile
	// the desired state tables to the BPF maps.
	datapath.Cell,

	// http.ServeMux for adding HTTP handlers
	cell.Provide(http.NewServeMux),

	// Simple HTTP API served over localhost:8080/
	cell.Invoke(registerHTTPServer),
)
