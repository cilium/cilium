// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"log/slog"
	"maps"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type driverNodeConfig struct {
	Node          string
	ClusterConfig string
	Config        *cilium_v2alpha1_api.CiliumNetworkDriverNodeConfigSpec

	Status reconciler.Status
}

func (nc *driverNodeConfig) GetName() string      { return nc.Node }
func (nc *driverNodeConfig) GetNamespace() string { return "" }

func (nc *driverNodeConfig) TableHeader() []string {
	return []string{
		"Node",
		"ClusterConfig",
		"Config",
		"Status",
		"Error",
	}
}

func (nc *driverNodeConfig) TableRow() []string {
	var config string
	data, err := json.Marshal(nc.Config)
	if err != nil {
		config = "<invalid configuration>"
	} else {
		config = string(data)
	}
	return []string{
		nc.Node,
		nc.ClusterConfig,
		config,
		nc.Status.Kind.String(),
		nc.Status.GetError(),
	}
}

var _ statedb.TableWritable = &driverNodeConfig{}

func (nc *driverNodeConfig) Clone() *driverNodeConfig {
	nc2 := *nc
	return &nc2
}

func (nc *driverNodeConfig) GetStatus() reconciler.Status {
	return nc.Status
}

func (nc *driverNodeConfig) SetStatus(newStatus reconciler.Status) *driverNodeConfig {
	nc.Status = newStatus
	return nc
}

const DriverNodeConfigTableName = "netdriver-node-config"

var (
	DriverNodeConfigIndex = statedb.Index[*driverNodeConfig, string]{
		Name: "name",
		FromObject: func(obj *driverNodeConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	DriverNodeConfigByClusterConfigIndex = statedb.Index[*driverNodeConfig, string]{
		Name: "clusterConfig",
		FromObject: func(obj *driverNodeConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.ClusterConfig))
		},
		FromKey:    index.String,
		FromString: index.FromString,
	}
)

func newDriverNodeConfigTable(db *statedb.DB) (statedb.RWTable[*driverNodeConfig], error) {
	tbl, err := statedb.NewTable(
		db,
		DriverNodeConfigTableName,
		DriverNodeConfigIndex,
		DriverNodeConfigByClusterConfigIndex,
	)
	return tbl, err
}

type driverNodeConfigOps struct {
	client cilium_v2alpha1.CiliumNetworkDriverNodeConfigInterface
}

func newDriverNodeConfigOps(lc cell.Lifecycle, log *slog.Logger, cs k8sClient.Clientset) reconciler.Operations[*driverNodeConfig] {
	if !cs.IsEnabled() {
		return nil
	}
	return &driverNodeConfigOps{client: cs.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs()}
}

func (ops *driverNodeConfigOps) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, obj *driverNodeConfig) error {
	cfg, err := ops.client.Get(ctx, obj.Node, metav1.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			_, err = ops.client.Create(ctx,
				&cilium_v2alpha1_api.CiliumNetworkDriverNodeConfig{
					ObjectMeta: metav1.ObjectMeta{Name: obj.Node},
					Spec:       *obj.Config.DeepCopy(),
				},
				metav1.CreateOptions{},
			)
		}
		return err
	}

	if cfg.Spec.DeepEqual(obj.Config) {
		return nil
	}

	newCfg := cfg.DeepCopy()
	newCfg.Spec = *obj.Config.DeepCopy()

	_, err = ops.client.Update(ctx, newCfg, metav1.UpdateOptions{})
	return err
}

func (ops *driverNodeConfigOps) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj *driverNodeConfig) error {
	err := ops.client.Delete(ctx, obj.Node, metav1.DeleteOptions{})
	if k8sErrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (ops *driverNodeConfigOps) Prune(ctx context.Context, _ statedb.ReadTxn, objects iter.Seq2[*driverNodeConfig, statedb.Revision]) error {
	k8sConfigs, err := ops.client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	configs := slices.Collect(maps.Keys(maps.Collect(objects)))

	var toDelete []string
	for _, k8sConfig := range k8sConfigs.Items {
		if !slices.ContainsFunc(configs, func(config *driverNodeConfig) bool {
			return config.Node == k8sConfig.Name
		}) {
			toDelete = append(toDelete, k8sConfig.Name)
		}
	}

	var errs []error
	for _, config := range toDelete {
		errs = append(errs, ops.client.Delete(ctx, config, metav1.DeleteOptions{}))
	}
	return errors.Join(errs...)
}

var _ reconciler.Operations[*driverNodeConfig] = &driverNodeConfigOps{}

func registerDriverNodeConfigReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*driverNodeConfig],
	tbl statedb.RWTable[*driverNodeConfig],
	daemonCfg *option.DaemonConfig,
	cs k8sClient.Clientset,
) error {
	if !cs.IsEnabled() || !daemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	_, err := reconciler.Register(
		params,
		tbl,
		(*driverNodeConfig).Clone,
		(*driverNodeConfig).SetStatus,
		(*driverNodeConfig).GetStatus,
		ops,
		nil, // no batch operations support
		reconciler.WithRefreshing(5*time.Minute, nil), // refresh to check for external changes in CiliumNetworkDriverNodeConfigs
	)
	return err
}
