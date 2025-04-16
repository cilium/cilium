// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Service defines the common properties for a load-balancing service. Associated with a
// service are a set of frontends that receive the traffic, and a set of backends to which
// the traffic is directed. A single frontend can map to a partial subset of backends depending
// on its properties.
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

	SessionAffinity        bool
	SessionAffinityTimeout time.Duration

	// ProxyRedirect if non-nil redirects the traffic going to the frontends
	// towards a locally running proxy.
	ProxyRedirect *ProxyRedirect

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
	SourceRanges []cidr.CIDR

	// PortNames maps a port name to a port number.
	PortNames map[string]uint16

	// TrafficDistribution if not default will influence how backends are chosen for
	// frontends associated with this service.
	TrafficDistribution TrafficDistribution

	// Properties are additional untyped properties that can carry feature
	// specific metadata about the service.
	Properties part.Map[string, any]
}

type TrafficDistribution string

const (
	// TrafficDistributionDefault will ignore any topology aware hints for choosing the backends.
	TrafficDistributionDefault = TrafficDistribution("")

	// TrafficDistributionPreferClose Indicates preference for routing traffic to topologically close backends,
	// that is to backends that are in the same zone.
	TrafficDistributionPreferClose = TrafficDistribution("PreferClose")
)

func (svc *Service) GetLBAlgorithmAnnotation() SVCLoadBalancingAlgorithm {
	return ToSVCLoadBalancingAlgorithm(svc.Annotations[annotation.ServiceLoadBalancingAlgorithm])
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

func (pr *ProxyRedirect) Equal(other *ProxyRedirect) bool {
	switch {
	case pr == nil && other == nil:
		return true
	case pr != nil && other != nil:
		return pr.ProxyPort == other.ProxyPort && slices.Equal(pr.Ports, other.Ports)
	default:
		return false
	}
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

	if svc.ProxyRedirect != nil {
		flags = append(flags, "ProxyRedirect="+svc.ProxyRedirect.String())
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

	if svc.Properties.Len() != 0 {
		// Since the property is an "any", we'll just show the keys.
		propKeys := make([]string, 0, svc.Properties.Len())
		for k := range svc.Properties.All() {
			propKeys = append(propKeys, k)
		}
		flags = append(flags, "Properties="+strings.Join(propKeys, ", "))
	}

	if svc.TrafficDistribution != TrafficDistributionDefault {
		flags = append(flags, "TrafficDistribution="+string(svc.TrafficDistribution))
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
			return index.NewKeySet(index.Stringer(obj.Name))
		},
		FromKey:    index.Stringer[ServiceName],
		FromString: index.FromString,
		Unique:     true,
	}

	ServiceByName = serviceNameIndex.Query
)

const (
	ServiceTableName = "services"
)

func NewServicesTable(cfg Config, db *statedb.DB) (statedb.RWTable[*Service], error) {
	tbl, err := statedb.NewTable(
		ServiceTableName,
		serviceNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
