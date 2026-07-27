// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Service defines the common properties for a load-balancing service. Associated with a
// service are a set of frontends that receive the traffic, and a set of backends to which
// the traffic is directed. A single frontend can map to a partial subset of backends depending
// on its properties.
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type Service struct {
	// Name is the fully qualified service name, e.g. (<cluster>/)<namespace>/<name>.
	Name ServiceName

	// Source is the data source from which this service was ingested from.
	Source source.Source

	// Labels associated with the service.
	Labels labels.Labels

	// Annotations associated with this service.
	Annotations map[string]string

	// Selector specifies which pods should be associated with this service. If
	// this is empty the backends associated to this service are managed externally
	// and not by Kubernetes.
	Selector map[string]string

	// NatPolicy defines whether we need NAT46/64 translation for backends.
	NatPolicy SVCNatPolicy

	// ExtTrafficPolicy controls how backends are selected for North-South traffic.
	// If set to "Local", only node-local backends are chosen.
	ExtTrafficPolicy SVCTrafficPolicy

	// IntTrafficPolicy controls how backends are selected for East-West traffic.
	// If set to "Local", only node-local backends are chosen.
	IntTrafficPolicy SVCTrafficPolicy

	// ForwardingMode controls whether DSR or SNAT should be used for the dispatch
	// to the backend. If undefined the default mode is used (--bpf-lb-mode).
	ForwardingMode SVCForwardingMode

	// SessionAffinity if true will enable the client IP based session affinity.
	SessionAffinity bool

	// SessionAffinityTimeout is the duration of inactivity before the session
	// affinity is cleared for a specific client IP.
	SessionAffinityTimeout time.Duration

	// LoadBalancerClass if set specifies the load-balancer class to be used
	// for a LoadBalancer service. If unset the default implementation is used.
	LoadBalancerClass *string

	// ProxyRedirects if non-empty redirects the traffic going to the frontends
	// towards a locally running proxy. Each entry can target different frontend
	// ports to different proxy ports.
	// NOTE: This is a slice and is shared by Clone() (shallow copy). Do not
	// mutate in place after cloning; always replace the whole field.
	// +deepequal-gen=false
	ProxyRedirects ProxyRedirects

	// HealthCheckNodePort defines on which port the node runs a HTTP health
	// check server which may be used by external loadbalancers to determine
	// if a node has local backends. This will only have effect if both
	// LoadBalancerIPs is not empty and ExtTrafficPolicy is SVCTrafficPolicyLocal.
	HealthCheckNodePort uint16

	// LoopbackHostPort defines that HostPort frontends for this service should
	// only be exposed internally to the node.
	LoopbackHostPort bool

	// SourceRanges if non-empty will restrict access to the service to the specified
	// client addresses.
	// +deepequal-gen=false
	SourceRanges []netip.Prefix

	// PortNames maps a port name to a port number.
	PortNames map[string]uint16

	// TrafficDistribution if not default will influence how backends are chosen for
	// frontends associated with this service.
	TrafficDistribution TrafficDistribution
}

type TrafficDistribution string

const (
	// TrafficDistributionDefault will ignore any topology aware hints for choosing the backends.
	TrafficDistributionDefault = TrafficDistribution("")

	// TrafficDistributionPreferSameZone indicates preference for routing traffic to backends
	// in the same zone as the client.
	TrafficDistributionPreferSameZone = TrafficDistribution("PreferSameZone")

	// TrafficDistributionPreferClose is a deprecated alias for PreferSameZone.
	TrafficDistributionPreferClose = TrafficDistribution("PreferClose")

	// TrafficDistributionPreferSameNode indicates preference for routing traffic to backends
	// on the same node as the client.
	TrafficDistributionPreferSameNode = TrafficDistribution("PreferSameNode")
)

// RequiresZoneUpdate returns true if the traffic distribution policy
// depends on node topology zone changes.
func (td TrafficDistribution) RequiresZoneUpdate() bool {
	return td == TrafficDistributionPreferSameZone ||
		td == TrafficDistributionPreferClose
}

func (svc *Service) DeepEqual(other *Service) bool {
	return svc.deepEqual(other) &&
		svc.ProxyRedirects.Equal(other.ProxyRedirects) &&
		slices.EqualFunc(svc.SourceRanges, other.SourceRanges,
			func(a, b netip.Prefix) bool {
				return a == b
			})
}

func (svc *Service) GetLBAlgorithmAnnotation() SVCLoadBalancingAlgorithm {
	return ToSVCLoadBalancingAlgorithm(svc.Annotations[annotation.ServiceLoadBalancingAlgorithm])
}

func (svc *Service) GetProxyDelegation() SVCProxyDelegation {
	if value, ok := annotation.Get(svc, annotation.ServiceProxyDelegation); ok {
		tmp := SVCProxyDelegation(strings.ToLower(value))
		if tmp == SVCProxyDelegationDelegateIfLocal {
			return tmp
		}
	}
	return SVCProxyDelegationNone
}

func (svc *Service) GetSourceRangesPolicy() SVCSourceRangesPolicy {
	if value, ok := annotation.Get(svc, annotation.ServiceSourceRangesPolicy); ok {
		if SVCSourceRangesPolicy(strings.ToLower(value)) == SVCSourceRangesPolicyDeny {
			return SVCSourceRangesPolicyDeny
		}
	}
	return SVCSourceRangesPolicyAllow
}

func (svc *Service) GetSourceRangesEnabled(svcType SVCType, lbSourceRangeAllTypes bool) bool {
	if lbSourceRangeAllTypes {
		return len(svc.SourceRanges) > 0
	}
	// loadBalancerSourceRanges also applies to ExternalIPs frontends of a LoadBalancer service.
	return len(svc.SourceRanges) > 0 &&
		(svcType == SVCTypeLoadBalancer || svcType == SVCTypeExternalIPs)
}

func (svc *Service) GetAnnotations() map[string]string {
	return svc.Annotations
}

type ProxyRedirect struct {
	ProxyPort uint16

	// Ports if non-empty will only redirect a frontend with a matching port.
	Ports []uint16
}

func (pr *ProxyRedirect) Redirects(port uint16) bool {
	if pr == nil {
		return false
	}
	return len(pr.Ports) == 0 || slices.Contains(pr.Ports, port)
}

func (pr *ProxyRedirect) String() string {
	if pr == nil {
		return ""
	}
	if len(pr.Ports) > 0 {
		return fmt.Sprintf("%d (ports: %v)", pr.ProxyPort, pr.Ports)
	}
	return strconv.FormatUint(uint64(pr.ProxyPort), 10)
}

// ProxyRedirects is a set of proxy redirects associated with a service.
type ProxyRedirects []ProxyRedirect

// Equal returns true if two ProxyRedirects are equal.
// Comparison is order-sensitive; this is safe because the slice order is
// determined by the stable ordering of CEC spec.services entries.
func (p ProxyRedirects) Equal(other ProxyRedirects) bool {
	if len(p) != len(other) {
		return false
	}
	for i := range p {
		if p[i].ProxyPort != other[i].ProxyPort || !slices.Equal(p[i].Ports, other[i].Ports) {
			return false
		}
	}
	return true
}

// ForPort finds the ProxyRedirect that matches the given frontend port.
// It prefers an exact port match over a wildcard (Ports is empty) match.
// Returns nil if no match is found. Nil entries are not expected.
func (p ProxyRedirects) ForPort(port uint16) *ProxyRedirect {
	var wildcard *ProxyRedirect
	for i := range p {
		if slices.Contains(p[i].Ports, port) {
			return &p[i]
		}
		if wildcard == nil && len(p[i].Ports) == 0 {
			wildcard = &p[i]
		}
	}
	return wildcard
}

// Redirects returns true if any ProxyRedirect in the set matches the given
// frontend port.
func (p ProxyRedirects) Redirects(port uint16) bool {
	return p.ForPort(port) != nil
}

// Empty reports whether the set contains no proxy redirects.
func (p ProxyRedirects) Empty() bool {
	return len(p) == 0
}

// String returns a human-readable representation of the redirects.
func (p ProxyRedirects) String() string {
	if len(p) == 0 {
		return ""
	}
	if len(p) == 1 {
		return p[0].String()
	}
	ss := make([]string, len(p))
	for i := range p {
		ss[i] = p[i].String()
	}
	return "[" + strings.Join(ss, ", ") + "]"
}

// Clone returns a shallow clone of the service, e.g. for updating a service with UpsertService. Fields that are references
// (e.g. Labels or Annotations) must be further cloned if mutated.
func (svc *Service) Clone() *Service {
	svc2 := *svc
	return &svc2
}

func (svc *Service) TableHeader() []string {
	// NOTE: Annotations and labels are not shown here as they're rarely interesting for debugging.
	// They are still available for inspection via "cilium-dbg statedb dump".
	return []string{
		"Name",
		"Source",
		"PortNames",
		"TrafficPolicy",
		"Flags",
	}
}

func (svc *Service) TableRow() []string {
	var trafficPolicy string
	if svc.ExtTrafficPolicy == svc.IntTrafficPolicy {
		trafficPolicy = string(svc.ExtTrafficPolicy)
	} else {
		trafficPolicy = fmt.Sprintf("Ext=%s, Int=%s", svc.ExtTrafficPolicy, svc.IntTrafficPolicy)
	}

	// Collapse the more rarely set fields into a single "Flags" column
	var flags []string

	if svc.SessionAffinity {
		flags = append(flags, "SessionAffinity="+svc.SessionAffinityTimeout.String())
	}

	if len(svc.SourceRanges) > 0 {
		cidrs := svc.SourceRanges
		ss := make([]string, len(cidrs))
		for i := range cidrs {
			ss[i] = cidrs[i].String()
		}
		flags = append(flags, "SourceRanges="+strings.Join(ss, ", "))
	}

	if p := svc.GetSourceRangesPolicy(); p == SVCSourceRangesPolicyDeny {
		flags = append(flags, "SourceRangesPolicy=deny")
	}

	if !svc.ProxyRedirects.Empty() {
		flags = append(flags, "ProxyRedirects="+svc.ProxyRedirects.String())
	}

	if svc.HealthCheckNodePort != 0 {
		flags = append(flags, fmt.Sprintf("HealthCheckNodePort=%d", svc.HealthCheckNodePort))
	}

	if svc.LoopbackHostPort {
		flags = append(flags, "LoopbackHostPort="+strconv.FormatBool(svc.LoopbackHostPort))
	}

	if alg := svc.GetLBAlgorithmAnnotation(); alg != SVCLoadBalancingAlgorithmUndef {
		flags = append(flags, "ExplicitLBAlgorithm="+alg.String())
	}

	if svc.ForwardingMode != SVCForwardingModeUndef {
		flags = append(flags, "ForwardingMode="+string(svc.ForwardingMode))
	}

	if svc.TrafficDistribution != TrafficDistributionDefault {
		flags = append(flags, "TrafficDistribution="+string(svc.TrafficDistribution))
	}

	if svc.LoadBalancerClass != nil {
		flags = append(flags, "LoadBalancerClass="+*svc.LoadBalancerClass)
	}

	sort.Strings(flags)

	return []string{
		svc.Name.String(),
		string(svc.Source),
		svc.showPortNames(),
		trafficPolicy,
		strings.Join(flags, ", "),
	}
}

func (svc *Service) showPortNames() string {
	var b strings.Builder
	n := len(svc.PortNames)
	for _, name := range slices.Sorted(maps.Keys(svc.PortNames)) {
		fmt.Fprintf(&b, "%s=%d", name, svc.PortNames[name])
		n--
		if n > 0 {
			b.WriteString(", ")
		}

	}
	return b.String()
}

var (
	serviceNameIndex = statedb.Index[*Service, ServiceName]{
		Name: "name",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(obj.Name.Key())
		},
		FromKey:    ServiceName.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	ServiceByName = serviceNameIndex.Query
)

const (
	ServiceTableName = "services"
)

func NewServicesTable(cfg Config, db *statedb.DB) (statedb.RWTable[*Service], error) {
	return statedb.NewTable(
		db,
		ServiceTableName,
		serviceNameIndex,
	)
}
