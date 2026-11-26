// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkconfig

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Group(
	cell.ProvidePrivate(newTableAndReflector),
)

// TableCell can be used in tests for providing the table, both as a statedb.RWTable and as a
// statedb.Table, without the associated k8s reflector.
var TableCell = cell.Provide(
	newTable,
	func(t statedb.RWTable[LocalResourceNetworkConfig]) statedb.Table[LocalResourceNetworkConfig] {
		return t
	},
)

// LocalResourceNetworkConfig is Cilium's internal model of a CiliumResourceNetworkConfig.
type LocalResourceNetworkConfig struct {
	Name string            `json:"name" yaml:"name"`
	Spec networkConfigSpec `json:"spec" yaml:"spec"`

	// UpdatedAt is the time when [LocalResourceNetworkConfig] was last updated, e.g. it shows when
	// last change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

// LongestPrefixSpecMatch returns the spec entry, for the provided address family, whose CIDR
// qualifies as longest prefix match. If no entry matches, the returned boolean is set to false.
func (c LocalResourceNetworkConfig) LongestPrefixSpecMatch(addr netip.Addr) (IPSpec, bool) {
	var ipSpec []IPSpec
	if addr.Is4() {
		ipSpec = c.Spec.IPv4
	} else {
		ipSpec = c.Spec.IPv6
	}
	return longestPrefixIPSpecMatch(ipSpec, addr)
}

func longestPrefixIPSpecMatch(ipSpec []IPSpec, addr netip.Addr) (IPSpec, bool) {
	found := false
	var entry IPSpec
	for i := range ipSpec {
		spec := &ipSpec[i]
		if spec.CIDR.Contains(addr) && (!found || spec.CIDR.Bits() > entry.CIDR.Bits()) {
			entry = *spec
			found = true
		}
	}
	return entry, found
}

type networkConfigSpec struct {
	IPv4 []IPSpec `json:"ipv4,omitempty" yaml:"ipv4,omitempty"`
	IPv6 []IPSpec `json:"ipv6,omitempty" yaml:"ipv6,omitempty"`
}

type IPSpec struct {
	CIDR         netip.Prefix        `json:"cidr" yaml:"cidr"`
	PrefixLength *int                `json:"prefixLength,omitempty" yaml:"prefixLength,omitempty"`
	Routes       []IPStaticRouteSpec `json:"routes,omitempty" yaml:"routes,omitempty"`
}

// GetPrefixLength returns the prefix length field value if available, and the CIDR's prefix length
// otherwise.
func (s *IPSpec) GetPrefixLength() int {
	if s.PrefixLength == nil {
		// note: the CIDR is valid, so Bits() doesn't return -1.
		return s.CIDR.Bits()
	}
	return *s.PrefixLength
}

type IPStaticRouteSpec struct {
	Destination netip.Prefix `json:"destination" yaml:"destination"`
	Gateway     *netip.Addr  `json:"gateway,omitempty" yaml:"gateway,omitempty"`
}

func (c LocalResourceNetworkConfig) GetName() string      { return c.Name }
func (c LocalResourceNetworkConfig) GetNamespace() string { return "" }

func (c LocalResourceNetworkConfig) TableHeader() []string {
	return []string{
		"Name",
		"IPv4",
		"IPv6",
		"Age",
	}
}

func (c LocalResourceNetworkConfig) TableRow() []string {
	return []string{
		c.Name,
		showIPSpecs(c.Spec.IPv4),
		showIPSpecs(c.Spec.IPv6),
		duration.HumanDuration(time.Since(c.UpdatedAt)),
	}
}

// Statically check that LocalResourceNetworkConfig implements statedb.TableWritable.
var _ statedb.TableWritable = LocalResourceNetworkConfig{}

func showIPSpecs(specs []IPSpec) string {
	var b strings.Builder
	for i, s := range specs {
		if i > 0 {
			b.WriteString(", ")
		}
		writeIPSpec(&b, s)
	}
	return b.String()
}

func writeIPSpec(b *strings.Builder, s IPSpec) {
	b.WriteString(s.CIDR.String())
	if s.PrefixLength != nil {
		b.WriteString(" PrefixLength=")
		b.WriteString(strconv.FormatUint(uint64(*s.PrefixLength), 10))
	}
	if len(s.Routes) > 0 {
		b.WriteString(" Routes=[")
		for i, r := range s.Routes {
			if i > 0 {
				b.WriteString(", ")
			}
			writeRoute(b, r)
		}
		b.WriteRune(']')
	}
}

func writeRoute(b *strings.Builder, r IPStaticRouteSpec) {
	b.WriteString(r.Destination.String())
	if r.Gateway != nil && r.Gateway.IsValid() {
		b.WriteString(" via ")
		b.WriteString(r.Gateway.String())
	}
}

const tableName = "k8s-cilium-resource-netconfigs"

var (
	tableByNameIndex = statedb.Index[LocalResourceNetworkConfig, string]{
		Name: "name",
		FromObject: func(obj LocalResourceNetworkConfig) index.KeySet {
			return index.NewKeySet(index.String(obj.GetName()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	// TableByNameQuery allows to query resource network config by name.
	TableByNameQuery = tableByNameIndex.Query
)

// newTableAndReflector returns a new statedb table holding resource network config information and
// associates a k8s reflector to it if k8s support is enabled.
func newTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset,
	crdSync promise.Promise[synced.CRDSync],
	driverCfg config.Config) (statedb.Table[LocalResourceNetworkConfig], error) {
	if !driverCfg.Enabled {
		return nil, nil
	}

	table, err := newTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return table, nil
	}

	reflCfg := newReflectorConfig(cs, crdSync, table)
	err = k8s.RegisterReflector(jg, db, reflCfg)
	return table, err
}

func newTable(db *statedb.DB) (statedb.RWTable[LocalResourceNetworkConfig], error) {
	return statedb.NewTable(db, tableName, tableByNameIndex)
}

func newReflectorConfig(cs client.Clientset, crdSync promise.Promise[synced.CRDSync],
	configs statedb.RWTable[LocalResourceNetworkConfig]) k8s.ReflectorConfig[LocalResourceNetworkConfig] {
	lw := utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumResourceNetworkConfigs())
	return k8s.ReflectorConfig[LocalResourceNetworkConfig]{
		Name:          "cilium-resource-network-config-k8s-reflector",
		Table:         configs,
		ListerWatcher: lw,
		MetricScope:   "CiliumResourceNetworkConfig",
		Transform:     toConfig,
		CRDSync:       crdSync,
	}
}

// toConfig transforms a v2alpha1.CiliumResourceNetworkConfig into a LocalResourceNetworkConfig.
func toConfig(_ statedb.ReadTxn, obj any) (LocalResourceNetworkConfig, bool) {
	cfg, ok := obj.(*v2alpha1.CiliumResourceNetworkConfig)
	if !ok {
		return LocalResourceNetworkConfig{}, false
	}

	spec := networkConfigSpec{
		IPv4: make([]IPSpec, 0, len(cfg.Spec.IPv4)),
		IPv6: make([]IPSpec, 0, len(cfg.Spec.IPv6)),
	}

	for specIdx := range cfg.Spec.IPv4 {
		ipv4Spec, isValid := parseIPv4Spec(&cfg.Spec.IPv4[specIdx])
		if !isValid {
			return LocalResourceNetworkConfig{}, false
		}
		spec.IPv4 = append(spec.IPv4, ipv4Spec)
	}

	for specIdx := range cfg.Spec.IPv6 {
		ipv6Spec, isValid := parseIPv6Spec(&cfg.Spec.IPv6[specIdx])
		if !isValid {
			return LocalResourceNetworkConfig{}, false
		}
		spec.IPv6 = append(spec.IPv6, ipv6Spec)
	}

	return LocalResourceNetworkConfig{
		Name:      cfg.Name,
		Spec:      spec,
		UpdatedAt: time.Now(),
	}, true
}

func parseIPv4Spec(spec *v2alpha1.IPv4NetworkConfigSpec) (IPSpec, bool) {
	cidr, err := netip.ParsePrefix(spec.CIDR)
	if err != nil {
		return IPSpec{}, false
	}
	var prefixLength *int
	if spec.PrefixLength != nil {
		prefixLength = new(int(*spec.PrefixLength))
	}

	routes := make([]IPStaticRouteSpec, 0, len(spec.Routes))
	for routeIdx := range spec.Routes {
		route := &spec.Routes[routeIdx]
		parsedRoute, isValid := parseRoute(route.Destination, route.Gateway)
		if !isValid {
			return IPSpec{}, false
		}
		routes = append(routes, parsedRoute)
	}
	return IPSpec{
		CIDR:         cidr,
		PrefixLength: prefixLength,
		Routes:       routes,
	}, true
}

func parseIPv6Spec(spec *v2alpha1.IPv6NetworkConfigSpec) (IPSpec, bool) {
	cidr, err := netip.ParsePrefix(spec.CIDR)
	if err != nil {
		return IPSpec{}, false
	}
	var prefixLength *int
	if spec.PrefixLength != nil {
		prefixLength = new(int(*spec.PrefixLength))
	}

	routes := make([]IPStaticRouteSpec, 0, len(spec.Routes))
	for routeIdx := range spec.Routes {
		route := &spec.Routes[routeIdx]
		parsedRoute, isValid := parseRoute(route.Destination, route.Gateway)
		if !isValid {
			return IPSpec{}, false
		}
		routes = append(routes, parsedRoute)
	}
	return IPSpec{
		CIDR:         cidr,
		PrefixLength: prefixLength,
		Routes:       routes,
	}, true
}

func parseRoute(destination string, gateway *string) (IPStaticRouteSpec, bool) {
	dst, err := netip.ParsePrefix(destination)
	if err != nil {
		return IPStaticRouteSpec{}, false
	}

	var gw *netip.Addr
	if gateway != nil {
		parsed, err := netip.ParseAddr(*gateway)
		if err != nil {
			return IPStaticRouteSpec{}, false
		}
		gw = &parsed
	}

	return IPStaticRouteSpec{Destination: dst, Gateway: gw}, true
}
