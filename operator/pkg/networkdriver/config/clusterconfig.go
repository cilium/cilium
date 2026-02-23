// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

type driverClusterConfig struct {
	Name         string                                                `json:"name" yaml:"name"`
	NodeConfig   cilium_v2alpha1_api.CiliumNetworkDriverNodeConfigSpec `json:"nodeConfig" yaml:"nodeConfig"`
	NodeSelector labels.Selector                                       `json:"nodeSelector,omitempty" yaml:"nodeSelector,omitempty"`
	Conditions   []metav1.Condition                                    `json:"conditions,omitempty" yaml:"conditions,omitempty"`

	// UpdatedAt is the time when [driverClusterConfig] was last updated, e.g. it
	// shows when last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (cc driverClusterConfig) GetName() string      { return cc.Name }
func (cc driverClusterConfig) GetNamespace() string { return "" }

func (cc driverClusterConfig) TableHeader() []string {
	return []string{
		"Name",
		"NodeConfig",
		"NodeSelector",
		"Conditions",
		"Age",
	}
}

func (cc driverClusterConfig) TableRow() []string {
	var config string
	data, err := json.Marshal(cc.NodeConfig)
	if err != nil {
		config = "<invalid configuration>"
	} else {
		config = string(data)
	}

	var sb strings.Builder
	for i := 0; i < len(cc.Conditions); i++ {
		sb.WriteString(cc.Conditions[i].Type)
		sb.WriteRune(':')
		sb.WriteString(string(cc.Conditions[i].Status))
		if i < len(cc.Conditions)-1 {
			sb.WriteRune(',')
		}
	}

	return []string{
		cc.Name,
		config,
		cc.NodeSelector.String(),
		sb.String(),
		duration.HumanDuration(time.Since(cc.UpdatedAt)),
	}
}

const DriverClusterConfigTableName = "k8s-netdriver-cluster-config"

var (
	DriverClusterConfigIndex = statedb.Index[driverClusterConfig, string]{
		Name: "name",
		FromObject: func(obj driverClusterConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey: index.String,
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}

	DriverClusterConfigByName = DriverClusterConfigIndex.Query
)

func newDriverClusterConfigTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset, daemonCfg *option.DaemonConfig) (statedb.Table[driverClusterConfig], error) {
	if !daemonCfg.EnableCiliumNetworkDriver {
		return nil, nil
	}

	driverClusterConfigs, err := NewDriverClusterConfigTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return driverClusterConfigs, nil
	}

	cfg := driverClusterConfigReflectorConfig(cs, driverClusterConfigs)
	err = k8s.RegisterReflector(jg, db, cfg)
	return driverClusterConfigs, err
}

func NewDriverClusterConfigTable(db *statedb.DB) (statedb.RWTable[driverClusterConfig], error) {
	return statedb.NewTable(
		db,
		DriverClusterConfigTableName,
		DriverClusterConfigIndex,
	)
}

func driverClusterConfigReflectorConfig(cs client.Clientset, configs statedb.RWTable[driverClusterConfig]) k8s.ReflectorConfig[driverClusterConfig] {
	lw := utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs())
	return k8s.ReflectorConfig[driverClusterConfig]{
		Name:          "cilium-netdriver-cluster-config-k8s-reflector",
		Table:         configs,
		ListerWatcher: lw,
		MetricScope:   "CiliumNetworkDriverClusterConfig",
		Transform: func(_ statedb.ReadTxn, obj any) (driverClusterConfig, bool) {
			cfg, ok := obj.(*v2alpha1.CiliumNetworkDriverClusterConfig)
			if !ok {
				return driverClusterConfig{}, false
			}
			var nodeSel labels.Selector
			if cfg.Spec.NodeSelector == nil {
				nodeSel = labels.Everything()
			} else {
				sel, err := slimv1.LabelSelectorAsSelector(cfg.Spec.NodeSelector)
				if err != nil {
					return driverClusterConfig{}, false
				}
				nodeSel = sel
			}
			return driverClusterConfig{
				Name:         cfg.Name,
				NodeConfig:   cfg.Spec.Spec,
				NodeSelector: nodeSel,
				Conditions:   cfg.Status.Conditions,
				UpdatedAt:    time.Now(),
			}, true
		},
	}
}
