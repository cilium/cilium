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

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/time"
)

type CEC struct {
	Name k8sTypes.NamespacedName
	Spec *ciliumv2.CiliumEnvoyConfigSpec

	Selector         labels.Selector `json:"-" yaml:"-"`
	SelectsLocalNode bool
	Listeners        part.Map[string, uint16]

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

type EnvoyResource struct {
	Name      CECName
	Resources envoy.Resources
	Redirects map[loadbalancer.ServiceName]*experimental.ProxyRedirect `json:"-"`

	ReconciledResources *envoy.Resources
	ReconciledRedirects map[loadbalancer.ServiceName]*experimental.ProxyRedirect `json:"-"`

	Status reconciler.Status
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

func (r *EnvoyResource) TableRow() []string {
	return []string{
		r.Name.String(),
		r.showListeners(),
		r.showEndpoints(),
		string(r.Status.Kind),
		duration.HumanDuration(time.Since(r.Status.UpdatedAt)),
		r.Status.Error,
	}
}

const (
	EnvoyResourcesTableName = "envoy-resources"
)

var (
	envoyResourceNameIndex = statedb.Index[*EnvoyResource, CECName]{
		Name: "name",
		FromObject: func(obj *EnvoyResource) index.KeySet {
			return index.NewKeySet(index.String(obj.Name.String()))
		},
		FromKey: index.Stringer[CECName],
		Unique:  true,
	}

	EnvoyResourceByName = envoyResourceNameIndex.Query
)

func NewEnvoyResourcesTable(db *statedb.DB) (statedb.RWTable[*EnvoyResource], error) {
	tbl, err := statedb.NewTable(
		EnvoyResourcesTableName,
		envoyResourceNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
