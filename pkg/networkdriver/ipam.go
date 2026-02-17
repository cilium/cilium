// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/duration"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// AddrAddRetryInterval is the initial interval for the exponential backoff between
	// subsequent "address add request" retries to the IPAM manager.
	// This is needed when requesting an IP address from a not yet ready pool, in order
	// to let the operator handle the new request and reserve a CIDR for the node.
	AddrAddRetryInterval = time.Second

	// AddrAddMaxRetries is the maximum number of "address add request" retries before
	// failing the operation.
	AddrAddMaxRetries = 25

	// ResourceIPAMMultiPoolPreAllocation defines the pre-allocation value for each resource
	// IPAM pool.
	ResourceIPAMMultiPoolPreAllocation = "resource-ipam-multi-pool-pre-allocation"
)

type ipamAction string

const (
	addrAdd ipamAction = "add"
	addrDel ipamAction = "del"
)

var resourceIPAM = cell.Group(
	cell.Config(defaultIPAMConfig),

	cell.ProvidePrivate(
		newResourceIPPoolTableAndReflector,
		newMultiPoolManager,
	),
)

type IPAMConfig struct {
	ResourceIPAMMultiPoolPreAllocation map[string]string
}

var defaultIPAMConfig = IPAMConfig{}

func (cfg IPAMConfig) Flags(flags *pflag.FlagSet) {
	flags.StringToString(ResourceIPAMMultiPoolPreAllocation, cfg.ResourceIPAMMultiPoolPreAllocation,
		fmt.Sprintf("Defines the minimum number of IPs for DRA resources a node should pre-allocate from each pool (default %s=8)", defaults.IPAMDefaultIPPool))
}

func newMultiPoolManager(
	Logger *slog.Logger,
	DaemonCfg *option.DaemonConfig,
	LocalNode daemonK8s.LocalCiliumNodeResource,
	ClientSet k8sClient.Clientset,
	JobGroup job.Group,
	Cfg IPAMConfig,
) *ipam.MultiPoolManager {
	if !ClientSet.IsEnabled() || !DaemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	preallocMap, err := ipam.ParseMultiPoolPreAllocMap(Cfg.ResourceIPAMMultiPoolPreAllocation)
	if err != nil {
		Logger.Error("Invalid flag value",
			logfields.Flag, ResourceIPAMMultiPoolPreAllocation,
			logfields.Error, err)
		return nil
	}

	return ipam.NewMultiPoolManager(ipam.MultiPoolManagerParams{
		Logger:               Logger,
		IPv4Enabled:          DaemonCfg.IPv4Enabled(),
		IPv6Enabled:          DaemonCfg.IPv6Enabled(),
		CiliumNodeUpdateRate: DaemonCfg.IPAMCiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 LocalNode,
		CNClient:             ClientSet.CiliumV2().CiliumNodes(),
		JobGroup:             JobGroup,
		PoolsFromResource: func(cn *v2.CiliumNode) *ipamtypes.IPAMPoolSpec {
			return &cn.Spec.IPAM.ResourcePools
		},
	})
}

type resourceIPPool struct {
	Name         string                 `json:"name" yaml:"name"`
	IPv4         *v2alpha1.IPv4PoolSpec `json:"ipv4" yaml:"ipv4"`
	IPv6         *v2alpha1.IPv6PoolSpec `json:"ipv6" yaml:"ipv6"`
	NodeSelector labels.Selector        `json:"nodeSelector,omitempty" yaml:"nodeSelector,omitempty"`

	// UpdatedAt is the time when [resourceIPPool] was last updated, e.g. it
	// shows when last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (p resourceIPPool) GetName() string      { return p.Name }
func (p resourceIPPool) GetNamespace() string { return "" }

func (p resourceIPPool) TableHeader() []string {
	return []string{
		"Name",
		"IPv4 CIDRs",
		"IPv4 MaskSize",
		"IPv6 CIDRs",
		"IPv6 MaskSize",
		"Node Selector",
		"Age",
	}
}

func (p resourceIPPool) TableRow() []string {
	showCIDRs := func(cidrs []v2alpha1.PoolCIDR) string {
		var b strings.Builder
		for i := 0; i < len(cidrs); i++ {
			b.WriteString(string(cidrs[i]))
			if i != len(cidrs)-1 {
				b.WriteString(", ")
			}
		}
		return b.String()
	}

	var (
		v4CIDRs, v6CIDRs   string
		v4MaskSz, v6MaskSz string
	)
	if p.IPv4 != nil {
		v4CIDRs = showCIDRs(p.IPv4.CIDRs)
	}
	if p.IPv6 != nil {
		v6CIDRs = showCIDRs(p.IPv6.CIDRs)
	}

	return []string{
		p.Name,
		v4CIDRs, v4MaskSz,
		v6CIDRs, v6MaskSz,
		p.NodeSelector.String(),
		duration.HumanDuration(time.Since(p.UpdatedAt)),
	}
}

const ResourceIPPoolTableName = "k8s-cilium-resource-ip-pools"

var (
	ResourceIPPoolIndex = statedb.Index[resourceIPPool, string]{
		Name: "name",
		FromObject: func(obj resourceIPPool) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey: index.String,
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}

	ResourceIPPoolByName = ResourceIPPoolIndex.Query
)

func newResourceIPPoolTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset, crdSync promise.Promise[synced.CRDSync], daemonCfg *option.DaemonConfig) (statedb.Table[resourceIPPool], error) {
	if !daemonCfg.EnableCiliumNetworkDriver {
		return nil, nil
	}

	resourceIPPools, err := NewResourceIPPoolTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return resourceIPPools, nil
	}

	cfg := resourceIPPoolReflectorConfig(cs, crdSync, resourceIPPools)
	err = k8s.RegisterReflector(jg, db, cfg)
	return resourceIPPools, err
}

func NewResourceIPPoolTable(db *statedb.DB) (statedb.RWTable[resourceIPPool], error) {
	return statedb.NewTable(
		db,
		ResourceIPPoolTableName,
		ResourceIPPoolIndex,
	)
}

func resourceIPPoolReflectorConfig(cs client.Clientset, crdSync promise.Promise[synced.CRDSync], pools statedb.RWTable[resourceIPPool]) k8s.ReflectorConfig[resourceIPPool] {
	lw := utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumResourceIPPools())
	return k8s.ReflectorConfig[resourceIPPool]{
		Name:          "cilium-resource-ip-pool-k8s-reflector",
		Table:         pools,
		ListerWatcher: lw,
		MetricScope:   "CiliumResourceIPPool",
		Transform: func(_ statedb.ReadTxn, obj any) (resourceIPPool, bool) {
			pool, ok := obj.(*v2alpha1.CiliumResourceIPPool)
			if !ok {
				return resourceIPPool{}, false
			}
			var nodeSel labels.Selector
			if pool.Spec.NodeSelector == nil {
				nodeSel = labels.Everything()
			} else {
				sel, err := slimv1.LabelSelectorAsSelector(pool.Spec.NodeSelector)
				if err != nil {
					return resourceIPPool{}, false
				}
				nodeSel = sel
			}
			return resourceIPPool{
				Name:         pool.Name,
				IPv4:         pool.Spec.IPv4,
				IPv6:         pool.Spec.IPv6,
				NodeSelector: nodeSel,
				UpdatedAt:    time.Now(),
			}, true
		},
		CRDSync: crdSync,
	}
}
