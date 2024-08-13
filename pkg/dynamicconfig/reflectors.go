// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"github.com/cilium/statedb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var (
	CiliumConfigMap          = "cilium-config"
	CiliumConfigMapNamespace = "kube-system"

	// Lower number means higher priority
	// When adding a new source, the source priority needs to be updated here
	priorities = map[string]int{
		CiliumConfigMap: 0,
	}
)

func NewConfigMapReflector(cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig], c config) []k8s.ReflectorConfig[DynamicConfig] {
	if !cs.IsEnabled() || !c.EnableDynamicConfig {
		return []k8s.ReflectorConfig[DynamicConfig]{}
	}

	return []k8s.ReflectorConfig[DynamicConfig]{
		configMapReflector(CiliumConfigMap, cs, t),
	}
}

func configMapReflector(name string, cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig]) k8s.ReflectorConfig[DynamicConfig] {
	return k8s.ReflectorConfig[DynamicConfig]{
		Name:  "cm-" + name,
		Table: t,
		TransformMany: func(o any) []DynamicConfig {
			var entries []DynamicConfig
			cm := o.(*v1.ConfigMap).DeepCopy()
			for k, v := range cm.Data {
				dc := DynamicConfig{Key: Key{Name: k, Source: cm.Name}, Value: v}
				entries = append(entries, dc)
			}
			return entries
		},
		ListerWatcher: utils.ListerWatcherWithModifiers(
			utils.ListerWatcherFromTyped[*v1.ConfigMapList](cs.CoreV1().ConfigMaps(CiliumConfigMapNamespace)),
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + name).String()
			},
		),
		QueryAll: func(txn statedb.ReadTxn, t statedb.Table[DynamicConfig]) statedb.Iterator[DynamicConfig] {
			return statedb.Filter(
				t.All(txn),
				func(dc DynamicConfig) bool {
					return dc.Key.Source == name
				},
			)
		},
	}
}
