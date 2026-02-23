// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

type clusterConfigResourceParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	ClientSet       client.Clientset
	CRDSyncPromise  promise.Promise[synced.CRDSync] `optional:"true"`
	MetricsProvider workqueue.MetricsProvider
	DaemonConfig    *option.DaemonConfig
}

func clusterConfigResource(params clusterConfigResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumNetworkDriverClusterConfig], error) {
	if !params.ClientSet.IsEnabled() || !params.DaemonConfig.EnableCiliumNetworkDriver {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(params.ClientSet.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumNetworkDriverClusterConfig](params.Lifecycle, lw, params.MetricsProvider, resource.WithCRDSync(params.CRDSyncPromise)), nil
}

type driverClusterConfig struct {
	Name          string `json:"name" yaml:"name"`
	IsConflicting bool   `json:"isConflicting,omitempty" yaml:"isConflicting,omitempty"`

	Status reconciler.Status
}

func (cc *driverClusterConfig) GetName() string { return cc.Name }

func (cc *driverClusterConfig) TableHeader() []string {
	return []string{
		"Name",
		"IsConflicting",
		"Status",
		"Error",
	}
}

func (cc *driverClusterConfig) TableRow() []string {
	return []string{
		cc.Name,
		strconv.FormatBool(cc.IsConflicting),
		cc.Status.Kind.String(),
		cc.Status.GetError(),
	}
}

var _ statedb.TableWritable = &driverClusterConfig{}

func (cc *driverClusterConfig) Clone() *driverClusterConfig {
	cc2 := *cc
	return &cc2
}

func (cc *driverClusterConfig) GetStatus() reconciler.Status {
	return cc.Status
}

func (cc *driverClusterConfig) SetStatus(newStatus reconciler.Status) *driverClusterConfig {
	cc.Status = newStatus
	return cc
}

const DriverClusterConfigTableName = "netdriver-cluster-config"

var (
	DriverClusterConfigIndex = statedb.Index[*driverClusterConfig, string]{
		Name: "name",
		FromObject: func(obj *driverClusterConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func newDriverClusterConfigTable(db *statedb.DB) (statedb.RWTable[*driverClusterConfig], error) {
	tbl, err := statedb.NewTable(
		db,
		DriverClusterConfigTableName,
		DriverClusterConfigIndex,
	)
	return tbl, err
}

type driverClusterConfigOps struct {
	client cilium_v2alpha1.CiliumNetworkDriverClusterConfigInterface
}

func newDriverClusterConfigOps(lc cell.Lifecycle, log *slog.Logger, cs k8sClient.Clientset) reconciler.Operations[*driverClusterConfig] {
	if !cs.IsEnabled() {
		return nil
	}
	return &driverClusterConfigOps{client: cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()}
}

func (ops *driverClusterConfigOps) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, obj *driverClusterConfig) error {
	cfg, err := ops.client.Get(ctx, obj.Name, metav1.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			// cluster config has been deleted before we had a chance to update it, no need to retry
			return nil
		}
		return fmt.Errorf("failed to get network driver cluster config %s: %w", obj.Name, err)
	}

	if hasDesiredConflictStatus(cfg.Status.Conditions, obj.IsConflicting) {
		return nil
	}

	newCfg := cfg.DeepCopy()
	if obj.IsConflicting {
		meta.SetStatusCondition(&newCfg.Status.Conditions, metav1.Condition{
			Type:               cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Time{Time: time.Now()},
			Reason:             cilium_v2alpha1_api.NetworkDriverClusterConfigReasonConflict,
		})
	} else {
		meta.RemoveStatusCondition(
			&newCfg.Status.Conditions,
			cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict,
		)
	}

	_, err = ops.client.UpdateStatus(ctx, newCfg, metav1.UpdateOptions{})
	return err
}

func hasDesiredConflictStatus(conditions []metav1.Condition, isConflicting bool) bool {
	if isConflicting {
		return meta.IsStatusConditionTrue(conditions, cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict)
	}

	cond := meta.FindStatusCondition(
		conditions,
		cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict,
	)
	return cond == nil || cond.Status == metav1.ConditionFalse
}

func (ops *driverClusterConfigOps) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, _ *driverClusterConfig) error {
	return nil
}

func (ops *driverClusterConfigOps) Prune(ctx context.Context, _ statedb.ReadTxn, _ iter.Seq2[*driverClusterConfig, statedb.Revision]) error {
	return nil
}

var _ reconciler.Operations[*driverClusterConfig] = &driverClusterConfigOps{}

func registerDriverClusterConfigReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*driverClusterConfig],
	tbl statedb.RWTable[*driverClusterConfig],
	daemonCfg *option.DaemonConfig,
	cs k8sClient.Clientset,
) error {
	if !cs.IsEnabled() || !daemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	_, err := reconciler.Register(
		params,
		tbl,
		(*driverClusterConfig).Clone,
		(*driverClusterConfig).SetStatus,
		(*driverClusterConfig).GetStatus,
		ops,
		nil, // no batch operations support
	)
	return err
}
