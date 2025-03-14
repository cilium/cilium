// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"bytes"
	"fmt"
	"iter"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	BackendTableName = "backends"
)

// BackendParams defines the parameters of a backend for insertion into the backends table.
type BackendParams struct {
	Address loadbalancer.L3n4Addr

	// PortNames are the optional names for the ports. A frontend can specify which
	// backends to select by port name.
	PortNames []string

	// Weight of backend for load-balancing.
	Weight uint16

	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string

	// Zone where backend is located.
	ZoneID uint8

	// Source of the backend.
	Source source.Source

	// State of the backend, e.g. active, quarantined or terminating.
	State loadbalancer.BackendState

	// Unhealthy marks a backend as unhealthy and overrides [State] to mark the backend
	// as quarantined. We require a separate field for active health checking to merge
	// with the original source of this backend. Negative is used here to allow the
	// zero value to mean that the backend is healthy.
	Unhealthy bool

	// UnhealthyUpdatedAt is the timestamp for when [Unhealthy] was last updated. Zero
	// value if never updated.
	UnhealthyUpdatedAt time.Time
}

// Backend is a composite of the per-service backend instances that share the same
// IP address and port.
type Backend struct {
	Address loadbalancer.L3n4Addr

	// Instances of this backend. A backend is always linked to a specific
	// service and the instances may call the backend by different name
	// (PortName) or they may come from  differents sources.
	// Instances may contain multiple [BackendInstance]s per service
	// coming from different sources. The version from the source with the
	// highest priority (smallest uint8) is used. This is needed for smooth
	// transitions when ownership of endpoints is passed between upstream
	// data sources.
	Instances part.Map[BackendInstanceKey, BackendParams]
}

type BackendInstanceKey struct {
	ServiceName    loadbalancer.ServiceName
	SourcePriority uint8
}

func (k BackendInstanceKey) Key() []byte {
	var buf bytes.Buffer
	buf.WriteString(k.ServiceName.String())
	if k.SourcePriority != 0 {
		buf.WriteByte(' ')
		buf.WriteByte(k.SourcePriority)
	}
	return buf.Bytes()
}

type backendWithRevision struct {
	*BackendParams
	Revision statedb.Revision
}

func (be *Backend) GetInstance(name loadbalancer.ServiceName) *BackendParams {
	// Return the instance matching the service name with highest priority
	// (lowest number)
	for _, inst := range be.instancesOfService(name) {
		return &inst
	}
	return nil
}

func (be *Backend) GetInstanceForFrontend(fe *Frontend) *BackendParams {
	serviceName := fe.ServiceName
	if fe.RedirectTo != nil {
		serviceName = *fe.RedirectTo
	}
	return be.GetInstance(serviceName)
}

func (be *Backend) GetInstanceFromSource(name loadbalancer.ServiceName, src source.Source) *BackendParams {
	for k, inst := range be.Instances.Prefix(BackendInstanceKey{ServiceName: name}) {
		if k.ServiceName == name && inst.Source == src {
			return &inst
		}
		break
	}
	return nil
}

func (be *Backend) String() string {
	return strings.Join(be.TableRow(), " ")
}

func (be *Backend) TableHeader() []string {
	return []string{
		"Address",
		"Instances",
		"Shadows",
		"NodeName",
	}
}

func (be *Backend) TableRow() []string {
	nodeName := ""
	for _, inst := range be.Instances.All() {
		if nodeName == "" {
			nodeName = inst.NodeName
		}
	}
	return []string{
		be.Address.StringWithProtocol(),
		showInstances(be),
		showShadows(be),
		nodeName,
	}
}

// showInstances shows the backend instances in the following forms:
// - no port name(s): "default/nginx"
// - port name(s): "default/nginx (http, http-alt)"
// - not active: "default/nginx [quarantined]"
// - not active, port name(s): "default/nginx [quarantined] (http, http-alt)"
func showInstances(be *Backend) string {
	var b strings.Builder
	for k, inst := range be.PreferredInstances() {
		b.WriteString(k.ServiceName.String())

		if inst.State != loadbalancer.BackendStateActive || inst.Unhealthy {
			b.WriteString(" [")
			if inst.Unhealthy {
				b.WriteString("unhealthy")
			} else {
				s, _ := inst.State.String()
				b.WriteString(s)
			}
			b.WriteRune(']')
		}
		if len(inst.PortNames) > 0 {
			b.WriteString(" (")
			for i, name := range inst.PortNames {
				b.WriteString(string(name))
				if i < len(inst.PortNames)-1 {
					b.WriteRune(' ')
				}
			}
			b.WriteRune(')')
		}
		b.WriteString(", ")
	}
	return strings.TrimSuffix(b.String(), ", ")
}

func showShadows(be *Backend) string {
	var (
		services           []string
		instances          []string
		emptyName, svcName loadbalancer.ServiceName
	)
	updateServices := func() {
		if len(instances) > 0 {
			services = append(services, fmt.Sprintf("%s [%s]", svcName.String(), strings.Join(instances, ", ")))
		}
	}
	for k, inst := range be.Instances.All() {
		if k.ServiceName != svcName {
			if svcName != emptyName {
				updateServices()
			}
			svcName = k.ServiceName
			instances = instances[:0]
			continue // Omit the instance that is already included in showInstances
		}
		instance := string(inst.Source)
		if len(inst.PortNames) > 0 {
			instance += fmt.Sprintf(" (%s)", strings.Join(inst.PortNames, " "))
		}
		instances = append(instances, instance)
	}
	updateServices()
	return strings.Join(services, ", ")
}

func (be *Backend) serviceNameKeys() index.KeySet {
	if be.Instances.Len() == 1 {
		// Avoid allocating the slice.
		for k := range be.PreferredInstances() {
			return index.NewKeySet(index.String(k.ServiceName.String()))
		}
	}
	keys := make([]index.Key, 0, be.Instances.Len()) // This may be more than enough if non-preferred instances exist.
	for k := range be.PreferredInstances() {
		keys = append(keys, index.String(k.ServiceName.String()))
	}
	return index.NewKeySet(keys...)
}

func (be *Backend) PreferredInstances() iter.Seq2[BackendInstanceKey, BackendParams] {
	return func(yield func(BackendInstanceKey, BackendParams) bool) {
		var svcName loadbalancer.ServiceName
		for k, v := range be.Instances.All() {
			if k.ServiceName != svcName {
				svcName = k.ServiceName
				if !yield(k, v) {
					break
				}
			} // Skip instances with the same ServiceName but lower (numerically larger) priorities.
		}

	}
}

func (be *Backend) instancesOfService(name loadbalancer.ServiceName) iter.Seq2[BackendInstanceKey, BackendParams] {
	return be.Instances.Prefix(BackendInstanceKey{name, 0})
}

func (be *Backend) release(name loadbalancer.ServiceName) (*Backend, bool) {
	instances := be.Instances
	for k := range be.instancesOfService(name) {
		instances = instances.Delete(k)
	}
	beCopy := *be
	beCopy.Instances = instances
	return &beCopy, beCopy.Instances.Len() == 0
}

func (be *Backend) releasePerSource(name loadbalancer.ServiceName, source source.Source) (*Backend, bool) {
	var keyToDelete *BackendInstanceKey
	for k, inst := range be.instancesOfService(name) {
		if inst.Source == source {
			keyToDelete = &k
			break
		}
	}
	if keyToDelete == nil {
		return be, be.Instances.Len() == 0
	}
	beCopy := *be
	beCopy.Instances = beCopy.Instances.Delete(*keyToDelete)
	return &beCopy, beCopy.Instances.Len() == 0
}

// Clone returns a shallow clone of the backend.
func (be *Backend) Clone() *Backend {
	be2 := *be
	return &be2
}

var (
	backendAddrIndex = statedb.Index[*Backend, loadbalancer.L3n4Addr]{
		Name: "address",
		FromObject: func(obj *Backend) index.KeySet {
			return index.NewKeySet(obj.Address.Bytes())
		},
		FromKey:    func(l loadbalancer.L3n4Addr) index.Key { return index.Key(l.Bytes()) },
		FromString: loadbalancer.L3n4AddrFromString,
		Unique:     true,
	}

	BackendByAddress = backendAddrIndex.Query

	backendServiceIndex = statedb.Index[*Backend, loadbalancer.ServiceName]{
		Name:       "service",
		FromObject: (*Backend).serviceNameKeys,
		FromKey:    index.Stringer[loadbalancer.ServiceName],
		FromString: index.FromString,
		Unique:     false,
	}

	BackendByServiceName = backendServiceIndex.Query
)

func NewBackendsTable(cfg Config, db *statedb.DB) (statedb.RWTable[*Backend], error) {
	if !cfg.EnableExperimentalLB {
		return nil, nil
	}
	tbl, err := statedb.NewTable(
		BackendTableName,
		backendAddrIndex,
		backendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
