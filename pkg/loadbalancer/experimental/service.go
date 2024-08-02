// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Service defines the common properties for a load-balancing service. Associated with a
// service are a set of frontends that receive the traffic, and a set of backends to which
// the traffic is directed. A single frontend can map to a partial subset of backends depending
// on its properties.
type Service struct {
	// Name is the fully qualified service name, e.g. (<cluster>/)<namespace>/<name>.
	Name loadbalancer.ServiceName

	// Source is the data source from which this service was ingested from.
	Source source.Source

	// Labels associated with the service.
	Labels labels.Labels

	// Annotations associated with this service.
	Annotations map[string]string

	// NatPolicy defines whether we need NAT46/64 translation for backends.
	NatPolicy loadbalancer.SVCNatPolicy

	// ExtTrafficPolicy controls how backends are selected for North-South traffic.
	// If set to "Local", only node-local backends are chosen.
	ExtTrafficPolicy loadbalancer.SVCTrafficPolicy

	// IntTrafficPolicy controls how backends are selected for East-West traffic.
	// If set to "Local", only node-local backends are chosen.
	IntTrafficPolicy loadbalancer.SVCTrafficPolicy

	SessionAffinity        bool
	SessionAffinityTimeout time.Duration

	// L7ProxyPort if set redirects the traffic going to the frontends associated
	// with this service to a layer 7 proxy running locally on this node.
	L7ProxyPort uint16

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

	// Properties are additional untyped properties that can carry feature
	// specific metadata about the service.
	Properties part.Map[string, any]
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
		"NatPolicy",
		"ExtTrafficPolicy",
		"IntTrafficPolicy",
		"SessionAffinity",
		"L7ProxyPort",
		"HealthCheckNodePort",
		"LoopbackHostPort",
		"SourceRanges",
	}
}

func (svc *Service) TableRow() []string {
	var sessionAffinity string
	if svc.SessionAffinity {
		sessionAffinity = svc.SessionAffinityTimeout.String()
	}

	showBool := func(v bool) string {
		if v {
			return "true"
		} else {
			return "false"
		}
	}

	showSourceRanges := func(cidrs []cidr.CIDR) string {
		ss := make([]string, len(cidrs))
		for i := range cidrs {
			ss[i] = cidrs[i].String()
		}
		return strings.Join(ss, ", ")
	}

	return []string{
		svc.Name.String(),
		string(svc.Source),
		string(svc.NatPolicy),
		string(svc.ExtTrafficPolicy),
		string(svc.IntTrafficPolicy),
		sessionAffinity,
		strconv.FormatUint(uint64(svc.L7ProxyPort), 10),
		strconv.FormatUint(uint64(svc.HealthCheckNodePort), 10),
		showBool(svc.LoopbackHostPort),
		showSourceRanges(svc.SourceRanges),
	}
}

var (
	serviceNameIndex = statedb.Index[*Service, loadbalancer.ServiceName]{
		Name: "name",
		FromObject: func(obj *Service) index.KeySet {
			return index.NewKeySet(index.Stringer(obj.Name))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  true,
	}

	ServiceByName = serviceNameIndex.Query
)

const (
	ServiceTableName = "services"
)

func NewServicesTable(db *statedb.DB) (statedb.RWTable[*Service], error) {
	tbl, err := statedb.NewTable(
		ServiceTableName,
		serviceNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
