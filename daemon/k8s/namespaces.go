// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"maps"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

type Namespace struct {
	Name        string            `json:"name" yaml:"name"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`

	// UpdatedAt is the time when [Namespace] was last updated, e.g. it
	// shows when last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (ns Namespace) GetName() string              { return ns.Name }
func (ns Namespace) GetNamespace() string         { return "" }
func (ns Namespace) GetLabels() map[string]string { return ns.Labels }

func (ns Namespace) TableHeader() []string {
	return []string{
		"Namespace",
		"Labels",
		"Annotations",
		"Age",
	}
}

func (ns Namespace) TableRow() []string {
	showMap := func(m map[string]string) string {
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
	return []string{
		ns.Name,
		showMap(ns.Labels),
		showMap(ns.Annotations),
		duration.HumanDuration(time.Since(ns.UpdatedAt)),
	}
}

const (
	NamespaceTableName = "k8s-namespaces"
)

var (
	NamespaceIndex  = newNameIndex[Namespace]()
	NamespaceByName = NamespaceIndex.Query

	NamespaceTableCell = cell.Provide(NewNamespaceTableAndReflector)
)

func NewNamespaceTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.Table[Namespace], error) {
	namespaces, err := NewNamespaceTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return namespaces, nil
	}

	cfg := namespaceReflectorConfig(cs, namespaces)
	err = k8s.RegisterReflector(jg, db, cfg)
	return namespaces, err
}

func NewNamespaceTable(db *statedb.DB) (statedb.RWTable[Namespace], error) {
	return statedb.NewTable(
		db,
		NamespaceTableName,
		NamespaceIndex,
	)
}

func namespaceReflectorConfig(cs client.Clientset, namespaces statedb.RWTable[Namespace]) k8s.ReflectorConfig[Namespace] {
	lw := utils.ListerWatcherFromTyped(cs.Slim().CoreV1().Namespaces())
	return k8s.ReflectorConfig[Namespace]{
		Name:          reflectorName,
		Table:         namespaces,
		ListerWatcher: lw,
		MetricScope:   "Namespace",
		Transform: func(_ statedb.ReadTxn, obj any) (Namespace, bool) {
			ns, ok := obj.(*slim_corev1.Namespace)
			if !ok {
				return Namespace{}, false
			}
			return Namespace{
				Name:        ns.Name,
				Labels:      ns.Labels,
				Annotations: ns.Annotations,
				UpdatedAt:   time.Now(),
			}, true
		},
	}
}
