// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// CEC is the agent model of the parsed Cilium(Clusterwide)EnvoyConfig.
// These are stored in the 'ciliumenvoyconfigs' table that can be inspected
// with "db/show ciliumenvoyconfigs" in "cilium-dbg shell".
type CEC struct {
	Name k8sTypes.NamespacedName
	Spec *ciliumv2.CiliumEnvoyConfigSpec

	Selector         labels.Selector `json:"-" yaml:"-"`
	SelectsLocalNode bool
	Listeners        part.Map[string, uint16]

	ServicePorts map[loadbalancer.ServiceName]sets.Set[string] `json:"-" yaml:"-"`

	// Resources is the parsed envoy.Resources with the endpoints filled in.
	Resources envoy.Resources
}

func (cec *CEC) Clone() *CEC {
	cec2 := *cec
	return &cec2
}

func (*CEC) TableHeader() []string {
	return []string{
		"Name",
		"Selected",
		"NodeSelector",
		"Services",
		"BackendServices",
		"Listeners",
	}
}

func (cec *CEC) TableRow() []string {
	var services, beServices, listeners []string
	for _, svcl := range cec.Spec.Services {
		services = append(services, svcl.Namespace+"/"+svcl.Name)
	}
	for _, svcl := range cec.Spec.BackendServices {
		beServices = append(beServices, svcl.Namespace+"/"+svcl.Name)
	}
	for name, port := range cec.Listeners.All() {
		listeners = append(listeners, fmt.Sprintf("%s:%d", name, port))
	}
	return []string{
		cec.Name.String(),
		strconv.FormatBool(cec.SelectsLocalNode),
		cec.Selector.String(),
		strings.Join(services, ", "),
		strings.Join(beServices, ", "),
		strings.Join(listeners, ", "),
	}
}

type CECName = k8sTypes.NamespacedName

const (
	CECTableName = "ciliumenvoyconfigs"
)

var (
	cecNameIndex = statedb.Index[*CEC, CECName]{
		Name: "name",
		FromObject: func(obj *CEC) index.KeySet {
			return index.NewKeySet(index.String(obj.Name.String()))
		},
		FromKey: index.Stringer[k8sTypes.NamespacedName],
		Unique:  true,
	}

	CECByName = cecNameIndex.Query

	cecServiceIndex = statedb.Index[*CEC, loadbalancer.ServiceName]{
		Name: "service",
		FromObject: func(obj *CEC) index.KeySet {
			keys := make([]index.Key, len(obj.Spec.Services))
			for i, svcl := range obj.Spec.Services {
				keys[i] = index.String(
					loadbalancer.ServiceName{
						Namespace: svcl.Namespace,
						Name:      svcl.Name,
					}.String(),
				)
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key loadbalancer.ServiceName) index.Key {
			return index.String(key.String())
		},
		Unique: false,
	}

	CECByServiceName = cecServiceIndex.Query
)

func NewCECTable(db *statedb.DB) (statedb.RWTable[*CEC], error) {
	tbl, err := statedb.NewTable(
		CECTableName,
		cecNameIndex,
		cecServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

type EnvoyResourceOrigin string

func (k EnvoyResourceOrigin) String() string {
	return string(k)
}

const (
	EnvoyResourceOriginCEC         = EnvoyResourceOrigin("cec")
	EnvoyResourceOriginBackendSync = EnvoyResourceOrigin("backendsync")
)

// EnvoyResourceName is the unique identifier for [EnvoyResource]. These can be created from
// to origins:
// - cec: derived from the Cilium(Clusterwide)EnvoyConfig. Name is the name of the CiliumEnvoyConfig.
// - backendsync: cluster load assignments derived from backends. Name is the name of the service.
type EnvoyResourceName struct {
	Origin    EnvoyResourceOrigin
	Cluster   string
	Namespace string
	Name      string
}

func (n EnvoyResourceName) String() string {
	var b strings.Builder
	b.WriteString(string(n.Origin))
	b.WriteRune(':')
	if n.Cluster != "" {
		b.WriteString(n.Cluster)
		b.WriteRune('/')
	}
	b.WriteString(n.Namespace)
	b.WriteRune('/')
	b.WriteString(n.Name)
	return b.String()
}

// EnvoyResource is either a "cec" resource created from CEC, or a "backendsync" resource
// created from a service that one ore more CECs refer to.
type EnvoyResource struct {
	Name   EnvoyResourceName
	Status reconciler.Status

	// Resources to reconcile with Envoy
	Resources envoy.Resources

	// ReconciledResources are the last resources that were successfully reconciled.
	// Used when updating or deleting to compute the delta.
	ReconciledResources *envoy.Resources

	// Redirects are the proxy redirects to set. Redirection of services is performed after
	// the resources have been reconciled to Envoy.
	Redirects part.Map[loadbalancer.ServiceName, *loadbalancer.ProxyRedirect]

	// ReconciledRedirects are the redirects that were successfully set.
	ReconciledRedirects part.Map[loadbalancer.ServiceName, *loadbalancer.ProxyRedirect]

	ReferencedServices part.Set[loadbalancer.ServiceName]

	// ClusterReferences to CECs. Only applicable for "backendsync" resources. This is
	// used to keep track of how many CECs refer to a "backendsync" resource (via service name).
	// When no references remain the "backendsync" resource is deleted.
	ClusterReferences clusterReferences `json:"-"`
}

func (r *EnvoyResource) ClusterServiceName() loadbalancer.ServiceName {
	return loadbalancer.ServiceName{
		Namespace: r.Name.Namespace,
		Name:      r.Name.Name,
		Cluster:   r.Name.Cluster,
	}
}

type clusterReference struct {
	CECName   CECName
	PortNames sets.Set[string]
}

type clusterReferences []clusterReference

func (refs clusterReferences) HasPortName(portName string) bool {
	for _, ref := range refs {
		if ref.PortNames.Has(portName) {
			return true
		}
	}
	return false
}

func (refs clusterReferences) Remove(cec CECName) clusterReferences {
	out := make([]clusterReference, 0, len(refs))
	for _, ref := range refs {
		if ref.CECName != cec {
			out = append(out, ref)
		}
	}
	return clusterReferences(out)
}

func (refs clusterReferences) Add(cec CECName, portNames sets.Set[string]) clusterReferences {
	out := make([]clusterReference, 0, len(refs)+1)
	for _, ref := range refs {
		if ref.CECName != cec {
			out = append(out, ref)
		}
	}
	out = append(out, clusterReference{CECName: cec, PortNames: portNames})
	return clusterReferences(out)
}

func (r *EnvoyResource) Key() index.Key {
	return index.String(r.Name.String())
}

func (r *EnvoyResource) SetStatus(newStatus reconciler.Status) *EnvoyResource {
	r.Status = newStatus
	return r
}

func (r *EnvoyResource) GetStatus() reconciler.Status {
	return r.Status
}

func (r *EnvoyResource) Clone() *EnvoyResource {
	r2 := *r
	return &r2
}

func (*EnvoyResource) TableHeader() []string {
	return []string{
		"Name",
		"Listeners",
		"Endpoints",
		"References",
		"Status",
		"Since",
		"Error",
	}
}

func (r *EnvoyResource) showListeners() string {
	names := make([]string, len(r.Resources.Listeners))
	for i := range r.Resources.Listeners {
		names[i] = r.Resources.Listeners[i].Name
	}
	return strings.Join(names, ", ")
}

func (r *EnvoyResource) showEndpoints() string {
	out := []string{}
	for _, la := range r.Resources.Endpoints {
		addrs := []string{}
		for _, ep := range la.Endpoints {
			for _, lep := range ep.LbEndpoints {
				ep := lep.GetEndpoint()
				if addr := ep.GetAddress(); addr != nil {
					if saddr := addr.GetSocketAddress(); saddr != nil {
						addrs = append(addrs, saddr.Address)
					}
				}
			}
		}
		out = append(out,
			la.ClusterName+": "+strings.Join(addrs, ", "))
	}
	return strings.Join(out, ", ")
}

func (r *EnvoyResource) showReferences() string {
	out := []string{}
	for _, ref := range r.ClusterReferences {
		out = append(out, ref.CECName.String())
	}
	return strings.Join(out, ", ")
}

func (r *EnvoyResource) TableRow() []string {
	return []string{
		r.Name.String(),
		r.showListeners(),
		r.showEndpoints(),
		r.showReferences(),
		string(r.Status.Kind),
		duration.HumanDuration(time.Since(r.Status.UpdatedAt)),
		r.Status.Error,
	}
}

const (
	EnvoyResourcesTableName = "envoy-resources"
)

var (
	envoyResourceNameIndex = statedb.Index[*EnvoyResource, EnvoyResourceName]{
		Name: "name",
		FromObject: func(obj *EnvoyResource) index.KeySet {
			return index.NewKeySet(obj.Key())
		},
		FromKey:    index.Stringer[EnvoyResourceName],
		FromString: index.FromString,
		Unique:     true,
	}
	EnvoyResourceByName = envoyResourceNameIndex.Query

	envoyResourceOriginIndex = statedb.Index[*EnvoyResource, EnvoyResourceOrigin]{
		Name: "kind",
		FromObject: func(obj *EnvoyResource) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Name.Origin)))
		},
		FromKey:    index.Stringer[EnvoyResourceOrigin],
		FromString: index.FromString,
		Unique:     false,
	}

	EnvoyResourceByOrigin = envoyResourceOriginIndex.Query
)

func NewEnvoyResourcesTable(db *statedb.DB) (statedb.RWTable[*EnvoyResource], error) {
	tbl, err := statedb.NewTable(
		EnvoyResourcesTableName,
		envoyResourceNameIndex,
		envoyResourceOriginIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
