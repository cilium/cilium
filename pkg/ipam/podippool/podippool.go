// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podippool

import (
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

// LocalPodIPPool is an internal model of pod IP pools on the cluster
type LocalPodIPPool struct {
	*api_v2alpha1.CiliumPodIPPool

	// UpdatedAt is the time when [LocalPodIPPool] was last updated, e.g. it
	// shows when the pool change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (p LocalPodIPPool) TableHeader() []string {
	return []string{
		"Name",
		"v4CIDRs",
		"v4MaskSize",
		"v6CIDRs",
		"v6MaskSize",
		"Flags",
	}
}

func (p LocalPodIPPool) TableRow() []string {
	// Handle optional IPv4 specification
	var v4Cidrs []string
	var v4MaskSize string
	if p.Spec.IPv4 != nil {
		v4Cidrs = make([]string, len(p.Spec.IPv4.CIDRs))
		for i := range p.Spec.IPv4.CIDRs {
			v4Cidrs[i] = string(p.Spec.IPv4.CIDRs[i])
		}
		v4MaskSize = strconv.FormatUint(uint64(p.Spec.IPv4.MaskSize), 10)
	} else {
		v4MaskSize = "-"
	}

	// Handle optional IPv6 specification
	var v6Cidrs []string
	var v6MaskSize string
	if p.Spec.IPv6 != nil {
		v6Cidrs = make([]string, len(p.Spec.IPv6.CIDRs))
		for i := range p.Spec.IPv6.CIDRs {
			v6Cidrs[i] = string(p.Spec.IPv6.CIDRs[i])
		}
		v6MaskSize = strconv.FormatUint(uint64(p.Spec.IPv6.MaskSize), 10)
	} else {
		v6MaskSize = "-"
	}

	flags := []string{}
	if v, ok := p.ObjectMeta.Annotations[annotation.IPAMSkipMasquerade]; ok && v == "true" {
		flags = append(flags, "SkipMasquerade=true")
	}

	return []string{
		p.Name,
		formatCIDRs(v4Cidrs),
		v4MaskSize,
		formatCIDRs(v6Cidrs),
		v6MaskSize,
		strings.Join(flags, ", "),
	}
}

func formatCIDRs(cidrs []string) string {
	if len(cidrs) > 3 {
		return strings.Join(append(cidrs[:2], "..."), ", ")
	}
	return strings.Join(cidrs, ", ")
}

const (
	TableName     = "podippools"
	reflectorName = "daemon-k8s"
)

var (
	NameIndex = statedb.Index[LocalPodIPPool, string]{
		Name: "name",
		FromObject: func(obj LocalPodIPPool) index.KeySet {
			return index.NewKeySet([]byte(obj.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	ByName = NameIndex.Query

	// TableCell provides the PodIPPool StateDB table and its k8s reflector.
	TableCell = cell.Module(
		"ipam-podippool-table",
		"PodIPPool StateDB Table",
		cell.Provide(NewTableAndReflector),
	)
)

// NewTableAndReflector returns the read-only Table[LocalPodIPPool] and registers
// the k8s reflector. These are combined to ensure any dependency on Table[LocalPodIPPool]
// will start after the reflector, ensuring that Start hooks can wait for the table
// to initialize.
func NewTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.Table[LocalPodIPPool], error) {
	pools, err := NewTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return pools, nil
	}

	cfg := reflectorConfig(cs, pools)
	err = k8s.RegisterReflector(jg, db, cfg)
	return pools, err
}

func NewTable(db *statedb.DB) (statedb.RWTable[LocalPodIPPool], error) {
	return statedb.NewTable(
		db,
		TableName,
		NameIndex,
	)
}

func reflectorConfig(cs client.Clientset, podIPPools statedb.RWTable[LocalPodIPPool]) k8s.ReflectorConfig[LocalPodIPPool] {
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumPodIPPools()),
	)
	return k8s.ReflectorConfig[LocalPodIPPool]{
		Name:          reflectorName,
		Table:         podIPPools,
		ListerWatcher: lw,
		MetricScope:   "PodIPPool",
		Transform: func(_ statedb.ReadTxn, obj any) (LocalPodIPPool, bool) {
			pool, ok := obj.(*api_v2alpha1.CiliumPodIPPool)
			if !ok {
				return LocalPodIPPool{}, false
			}
			return LocalPodIPPool{
				CiliumPodIPPool: pool,
				UpdatedAt:       time.Now(),
			}, true
		},
	}
}
