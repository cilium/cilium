package main

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const PodTableName = "pods"

var (
	// podNameIndex is the primary index for pods which indexes them by namespace+name.
	podNameIndex = statedb.Index[*v1.Pod, string]{
		Name: "name",
		FromObject: func(obj *v1.Pod) index.KeySet {
			return index.NewKeySet(index.String(obj.Namespace + "/" + obj.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	PodByName = podNameIndex.Query
)

// NewPodTable creates the pod table and registers it.
func NewPodTable(db *statedb.DB) (statedb.RWTable[*v1.Pod], error) {
	tbl, err := statedb.NewTable(
		PodTableName,
		podNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

// PodListerWatcher is the lister watcher for pod objects. This is separately
// defined so integration tests can provide their own if needed.
type PodListerWatcher cache.ListerWatcher

func newPodListerWatcher(log *slog.Logger, cs client.Clientset) PodListerWatcher {
	if !cs.IsEnabled() {
		log.Error("client not configured, please set --k8s-kubeconfig-path")
		return nil
	}
	return PodListerWatcher(utils.ListerWatcherFromTyped(cs.Slim().CoreV1().Pods("")))
}

// registerReflector creates and registers a reflector for pods.
func registerReflector(
	jg job.Group,
	lw PodListerWatcher,
	db *statedb.DB,
	pods statedb.RWTable[*v1.Pod],
) error {
	if lw == nil {
		return nil
	}
	cfg := k8s.ReflectorConfig[*v1.Pod]{
		Name:          "pods",
		Table:         pods,
		ListerWatcher: lw,
		// More options available to e.g. transform the objects.
	}
	return k8s.RegisterReflector(
		jg,
		db,
		cfg,
	)
}

// PodsCell provides Table[*v1.Pod] and registers a reflector to populate
// the table from the api-server.
var PodsCell = cell.Module(
	"pods",
	"Pods table",

	cell.ProvidePrivate(
		NewPodTable,
		newPodListerWatcher,
	),
	cell.Provide(statedb.RWTable[*v1.Pod].ToTable),
	cell.Invoke(registerReflector),
)
