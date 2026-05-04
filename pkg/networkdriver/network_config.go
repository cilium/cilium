// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

type resourceNetworkConfig struct {
	Name  string `json:"name" yaml:"name"`
	Specs []spec `json:"specs" yaml:"specs"`

	// UpdatedAt is the time when [resourceNetworkConfig] was last updated, e.g. it
	// shows when last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

type spec struct {
	NodeSelector labels.Selector `json:"nodeSelector,omitempty" yaml:"nodeSelector,omitempty"`
	IPPool       string          `json:"resourcePool" yaml:"resourcePool"`
	Vlan         uint16          `json:"vlan,omitempty" yaml:"vlan,omitempty"`
	IPv4NetMask  int             `json:"ipv4NetMask" yaml:"ipv4NetMask"`
	IPv4Routes   []route         `json:"ipv4Routes" yaml:"ipv4Routes"`
	IPv6NetMask  int             `json:"ipv6NetMask" yaml:"ipv6NetMask"`
	IPv6Routes   []route         `json:"ipv6Routes" yaml:"ipv6Routes"`
}

type route struct {
	Destination netip.Prefix `json:"destination" yaml:"destination"`
	Gateway     netip.Addr   `json:"gateway" yaml:"gateway"`
}

func (c resourceNetworkConfig) GetName() string      { return c.Name }
func (c resourceNetworkConfig) GetNamespace() string { return "" }

func (c resourceNetworkConfig) TableHeader() []string {
	return []string{
		"Name",
		"Specs",
		"Age",
	}
}

func (c resourceNetworkConfig) TableRow() []string {
	showRoutes := func(routes []route) string {
		var b strings.Builder
		for i := range len(routes) {
			route := routes[i]
			b.WriteRune('[')
			b.WriteString(route.Destination.String())
			b.WriteString(" via ")
			b.WriteString(route.Gateway.String())
			b.WriteRune(']')
			if i != len(routes)-1 {
				b.WriteString(", ")
			}
		}
		return b.String()
	}

	showSpecs := func(s spec) string {
		var b strings.Builder
		b.WriteRune('{')
		b.WriteString(s.NodeSelector.String())
		b.WriteString(": ")
		b.WriteString(s.IPPool)
		if s.Vlan != 0 {
			b.WriteString(", vlan ")
			b.WriteString(strconv.Itoa(int(s.Vlan)))
		}
		b.WriteString(", /")
		b.WriteString(strconv.Itoa(s.IPv4NetMask))
		b.WriteString(", ")
		b.WriteString(showRoutes(s.IPv4Routes))
		b.WriteString(", ")
		b.WriteString(strconv.Itoa(s.IPv6NetMask))
		b.WriteString(", /")
		b.WriteString(showRoutes(s.IPv6Routes))
		b.WriteRune('}')
		return b.String()
	}

	var b strings.Builder
	b.WriteRune('[')
	for i := 0; i < len(c.Specs); i++ {
		b.WriteString(showSpecs(c.Specs[i]))
		if i != len(c.Specs)-1 {
			b.WriteString("; ")
		}
	}
	b.WriteRune(']')

	return []string{
		c.Name,
		b.String(),
		duration.HumanDuration(time.Since(c.UpdatedAt)),
	}
}

const ResourceNetworkConfigTableName = "k8s-cilium-resource-netconfigs"

var (
	ResourceNetworkConfigIndex = statedb.Index[resourceNetworkConfig, string]{
		Name: "name",
		FromObject: func(obj resourceNetworkConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	ResourceNetworkConfigByName = ResourceNetworkConfigIndex.Query
)

func newResourceNetworkConfigTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset, crdSync promise.Promise[synced.CRDSync], daemonCfg *option.DaemonConfig) (statedb.Table[resourceNetworkConfig], error) {
	if !daemonCfg.EnableCiliumNetworkDriver {
		return nil, nil
	}

	resourceNetworkConfigs, err := NewResourceNetworkConfigTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return resourceNetworkConfigs, nil
	}

	cfg := resourceNetworkConfigReflectorConfig(cs, crdSync, resourceNetworkConfigs)
	err = k8s.RegisterReflector(jg, db, cfg)
	return resourceNetworkConfigs, err
}

func NewResourceNetworkConfigTable(db *statedb.DB) (statedb.RWTable[resourceNetworkConfig], error) {
	return statedb.NewTable(
		db,
		ResourceNetworkConfigTableName,
		ResourceNetworkConfigIndex,
	)
}

func resourceNetworkConfigReflectorConfig(cs client.Clientset, crdSync promise.Promise[synced.CRDSync], configs statedb.RWTable[resourceNetworkConfig]) k8s.ReflectorConfig[resourceNetworkConfig] {
	lw := utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumResourceNetworkConfigs())
	return k8s.ReflectorConfig[resourceNetworkConfig]{
		Name:          "cilium-resource-network-config-k8s-reflector",
		Table:         configs,
		ListerWatcher: lw,
		MetricScope:   "CiliumResourceNetworkConfig",
		Transform: func(_ statedb.ReadTxn, obj any) (resourceNetworkConfig, bool) {
			cfg, ok := obj.(*v2alpha1.CiliumResourceNetworkConfig)
			if !ok {
				return resourceNetworkConfig{}, false
			}

			specs := make([]spec, 0, len(cfg.Spec))
			for _, sp := range cfg.Spec {
				var nodeSel labels.Selector
				if sp.NodeSelector == nil {
					nodeSel = labels.Everything()
				} else {
					sel, err := slimv1.LabelSelectorAsSelector(sp.NodeSelector)
					if err != nil {
						return resourceNetworkConfig{}, false
					}
					nodeSel = sel
				}

				s := spec{
					NodeSelector: nodeSel,
					IPPool:       sp.IPPool,
					Vlan:         sp.VLAN,
				}

				if sp.IPv4 != nil {
					s.IPv4NetMask = int(sp.IPv4.NetMask)
					s.IPv4Routes = make([]route, 0, len(sp.IPv4.StaticRoutes))
					for _, r := range sp.IPv4.StaticRoutes {
						dst, err := netip.ParsePrefix(r.Destination)
						if err != nil {
							return resourceNetworkConfig{}, false
						}
						gw, err := netip.ParseAddr(r.Gateway)
						if err != nil {
							return resourceNetworkConfig{}, false
						}
						s.IPv4Routes = append(s.IPv4Routes, route{Destination: dst, Gateway: gw})
					}
				}

				if sp.IPv6 != nil {
					s.IPv6NetMask = int(sp.IPv6.NetMask)
					s.IPv6Routes = make([]route, 0, len(sp.IPv6.StaticRoutes))
					for _, r := range sp.IPv6.StaticRoutes {
						dst, err := netip.ParsePrefix(r.Destination)
						if err != nil {
							return resourceNetworkConfig{}, false
						}
						gw, err := netip.ParseAddr(r.Gateway)
						if err != nil {
							return resourceNetworkConfig{}, false
						}
						s.IPv6Routes = append(s.IPv6Routes, route{Destination: dst, Gateway: gw})
					}
				}

				specs = append(specs, s)
			}

			return resourceNetworkConfig{
				Name:      cfg.Name,
				Specs:     specs,
				UpdatedAt: time.Now(),
			}, true
		},
		CRDSync: crdSync,
	}
}
