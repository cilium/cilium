package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reflector"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
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

	client.Cell,
	cell.Invoke(func(cs client.Clientset) error {
		if !cs.IsEnabled() {
			return errors.New("Please provide --k8s-kubeconfig-path")
		}
		return nil
	}),

	statedb.Cell,
	job.Cell,

	KubernetesTables,

	cell.Invoke(registerHTTPServer),
)

var KubernetesTables = cell.Module(
	"kubernetes-tables",
	"Tables of Kubernetes objects",

	cell.ProvidePrivate(servicesTable, servicesConfig),
	cell.Provide(statedb.RWTable[*v1.Service].ToTable), // Provide Table[*Service]
	reflector.KubernetesCell[*Service](),

	cell.ProvidePrivate(backendsTable, endpointsConfig),
	cell.Provide(statedb.RWTable[*v1.Endpoints].ToTable), // Provide Table[*Backend]
	reflector.KubernetesCell[*Backend](),
)

var ServicesNameIndex = statedb.Index[*Service, string]{
	Name: "name",
	FromObject: func(s *Service) index.KeySet {
		return index.NewKeySet(index.String(s.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func servicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	table, err := statedb.NewTable[*Service]("services", ServicesNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}

func servicesConfig(cs client.Clientset, t statedb.RWTable[*Service]) reflector.KubernetesConfig[*Service] {
	return reflector.KubernetesConfig[*Service]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.ServiceList](cs.CoreV1().Services("")),
		Table:          t,
		Transform:      parseService,
	}
}

var BackendsNameIndex = statedb.Index[*Backend, string]{
	Name: "name",
	FromObject: func(b *Backend) index.KeySet {
		return index.NewKeySet(index.String(b.Service))
	},
	FromKey: index.String,
	Unique:  true,
}

func backendsTable(db *statedb.DB) (statedb.RWTable[*Backend], error) {
	table, err := statedb.NewTable[*Backend]("backends", BackendsNameIndex)
	if err == nil {
		return table, db.RegisterTable(table)
	}
	return nil, err
}

func endpointsConfig(cs client.Clientset, t statedb.RWTable[*Backend]) reflector.KubernetesConfig[*Backend] {
	return reflector.KubernetesConfig[*Backend]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.EndpointsList](cs.CoreV1().Endpoints("")),
		Table:          t,
		Transform:      parseEndpoints,
	}
}

func registerHTTPServer(
	lc hive.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB) {

	mux := http.NewServeMux()

	// For dumping the database:
	// curl -s http://localhost:8080/statedb | jq .
	mux.Handle("/statedb", db)

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
