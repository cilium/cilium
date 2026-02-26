// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type ciliumNode struct {
	Name        string            `json:"name" yaml:"name"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`

	// UpdatedAt is the time when [ciliumNode] was last updated, e.g. it
	// shows when last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (cn ciliumNode) GetName() string      { return cn.Name }
func (cn ciliumNode) GetNamespace() string { return "" }

func (cn ciliumNode) TableHeader() []string {
	return []string{
		"Name",
		"Labels",
		"Annotations",
		"Age",
	}
}

func (cn ciliumNode) TableRow() []string {
	return []string{
		cn.Name,
		showMap(cn.Labels),
		showMap(cn.Annotations),
		duration.HumanDuration(time.Since(cn.UpdatedAt)),
	}
}

const (
	CiliumNodeTableName = "k8s-cilium-nodes"
)

var (
	CiliumNodeIndex = statedb.Index[ciliumNode, string]{
		Name: "name",
		FromObject: func(obj ciliumNode) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey: index.String,
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
	CiliumNodeByName = CiliumNodeIndex.Query
)

func newCiliumNodeTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.Table[ciliumNode], error) {
	ciliumNodes, err := newCiliumNodeTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return ciliumNodes, nil
	}

	cfg := ciliumNodeReflectorConfig(cs, ciliumNodes)
	err = k8s.RegisterReflector(jg, db, cfg)
	return ciliumNodes, err
}

func newCiliumNodeTable(db *statedb.DB) (statedb.RWTable[ciliumNode], error) {
	return statedb.NewTable(
		db,
		CiliumNodeTableName,
		CiliumNodeIndex,
	)
}

func ciliumNodeReflectorConfig(cs client.Clientset, ciliumNodes statedb.RWTable[ciliumNode]) k8s.ReflectorConfig[ciliumNode] {
	lw := utils.ListerWatcherFromTyped(cs.CiliumV2().CiliumNodes())
	return k8s.ReflectorConfig[ciliumNode]{
		Name:          "cilium-node-k8s-reflector",
		Table:         ciliumNodes,
		ListerWatcher: lw,
		MetricScope:   "CiliumNode",
		Transform: func(_ statedb.ReadTxn, obj any) (ciliumNode, bool) {
			cn, ok := obj.(*cilium_v2_api.CiliumNode)
			if !ok {
				return ciliumNode{}, false
			}
			return ciliumNode{
				Name:        cn.Name,
				Labels:      cn.Labels,
				Annotations: cn.Annotations,
				UpdatedAt:   time.Now(),
			}, true
		},
	}
}

func showMap(m map[string]string) string {
	var b strings.Builder
	n := len(m)
	for _, k := range slices.Sorted(maps.Keys(m)) {
		b.WriteString(k)
		b.WriteRune('=')
		b.WriteString(m[k])
		n--
		if n > 0 {
			b.WriteString(", ")
		}
	}
	return b.String()
}
