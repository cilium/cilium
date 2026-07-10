// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/operator/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	corev1 "k8s.io/api/core/v1"
)

type ServiceAccount struct {
	*corev1.ServiceAccount
}

func (sa ServiceAccount) TableHeader() []string {
	return []string{"Namespace", "Name"}
}

func (sa ServiceAccount) TableRow() []string {
	return []string{sa.Namespace, sa.Name}
}

var _ statedb.TableWritable = ServiceAccount{}

var ServiceAccountNamespaceIndex = statedb.Index[ServiceAccount, string]{
	Name: "serviceaccount-namespace",
	FromObject: func(sa ServiceAccount) index.KeySet {
		return index.NewKeySet(index.String(sa.Namespace))
	},
	FromKey: index.String,
	Unique:  false,
}

var ServiceAccountNamespacedNameIndex = statedb.Index[ServiceAccount, string]{
	Name: "serviceaccount-name",
	FromObject: func(sa ServiceAccount) index.KeySet {
		return index.NewKeySet(index.String(sa.Namespace + "/" + sa.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func NewServiceAccountTable(jg job.Group, db *statedb.DB, cs client.Clientset, zcfg config.Config) (statedb.Table[ServiceAccount], error) {
	serviceAccounts, err := statedb.NewTable(
		db,
		"serviceaccounts",
		ServiceAccountNamespacedNameIndex,
		ServiceAccountNamespaceIndex,
	)
	if err != nil {
		return nil, err
	}
	if !cs.IsEnabled() || !zcfg.EnableZTunnel {
		return serviceAccounts, nil
	}

	cfg := serviceAccountReflectorConfig(cs, serviceAccounts)
	err = k8s.RegisterReflector(jg, db, cfg)
	return serviceAccounts, err
}

func serviceAccountReflectorConfig(cs client.Clientset, serviceAccounts statedb.RWTable[ServiceAccount]) k8s.ReflectorConfig[ServiceAccount] {
	lw := utils.ListerWatcherFromTyped(cs.CoreV1().ServiceAccounts(""))
	return k8s.ReflectorConfig[ServiceAccount]{
		Name:          "k8s-serviceaccounts",
		Table:         serviceAccounts,
		ListerWatcher: lw,
		MetricScope:   "ServiceAccount",
		Transform: func(txn statedb.ReadTxn, obj any) (ServiceAccount, bool) {
			serviceAccount, ok := obj.(*corev1.ServiceAccount)
			if !ok {
				return ServiceAccount{}, false
			}
			return ServiceAccount{ServiceAccount: serviceAccount}, true
		},
	}
}
