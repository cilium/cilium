// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"
	"sort"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	secureHost   = "secure"
	insecureHost = "insecure"
)

var _ translation.Translator = (*SharedIngressTranslator)(nil)

// SharedIngressTranslator is the translator from model to CiliumEnvoyConfig
// for Ingress.
//
// This translator is used for shared LB mode.
//   - only one instance of CiliumEnvoyConfig with two listeners (secure and
//     in-secure).
//   - no LB service and endpoint
type SharedIngressTranslator struct {
	name             string
	namespace        string
	secretsNamespace string
	enforceHTTPs     bool
}

// NewSharedIngressTranslator returns a new translator for shared ingress mode.
func NewSharedIngressTranslator(name, namespace, secretsNamespace string, enforceHTTPs bool) *SharedIngressTranslator {
	return &SharedIngressTranslator{
		name:             name,
		namespace:        namespace,
		secretsNamespace: secretsNamespace,
		enforceHTTPs:     enforceHTTPs,
	}
}

// Translate translates the model to CiliumEnvoyConfig.
func (i *SharedIngressTranslator) Translate(model *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.name,
			Namespace: i.namespace,
		},
	}

	cec.Spec.BackendServices = i.getBackendServices(model)
	cec.Spec.Services = i.getServices(model)
	cec.Spec.Resources = i.getResources(model)

	return cec, nil, nil, nil
}

func (i *SharedIngressTranslator) getBackendServices(m *model.Model) []*ciliumv2.Service {
	var res []*ciliumv2.Service

	for ns, v := range getNamespaceNamePortsMap(m) {
		for name, ports := range v {
			res = append(res, &ciliumv2.Service{
				Name:      name,
				Namespace: ns,
				Ports:     ports,
			})
		}
	}

	// Make sure the result is sorted by namespace and name to avoid any
	// nondeterministic behavior.
	sort.Slice(res, func(i, j int) bool {
		if res[i].Namespace != res[j].Namespace {
			return res[i].Namespace < res[j].Namespace
		}
		if res[i].Name != res[j].Name {
			return res[i].Name < res[j].Name
		}
		return res[i].Ports[0] < res[j].Ports[0]
	})
	return res
}

func (i *SharedIngressTranslator) getServices(_ *model.Model) []*ciliumv2.ServiceListener {
	return []*ciliumv2.ServiceListener{
		{
			Name:      i.name,
			Namespace: i.namespace,
		},
	}
}

func (i *SharedIngressTranslator) getResources(m *model.Model) []ciliumv2.XDSResource {
	listener, routeConfig, clusters := i.getListener(m), i.getRouteConfiguration(m), i.getClusters(m)
	res := make([]ciliumv2.XDSResource, 0, len(listener)+len(routeConfig)+len(clusters))
	res = append(res, listener...)
	res = append(res, routeConfig...)
	res = append(res, clusters...)
	return res
}

// getListener returns the listener for the given model. Only one single
// listener is returned for shared LB mode, tls and non-tls filters are
// applied by default.
func (i *SharedIngressTranslator) getListener(m *model.Model) []ciliumv2.XDSResource {
	var tls []*model.TLSSecret
	for _, h := range m.HTTP {
		if h.TLS != nil {
			tls = append(tls, h.TLS)
		}
	}

	l, _ := translation.NewListenerWithDefaults(fmt.Sprintf("%s-%s-listener", i.namespace, i.name), i.secretsNamespace, tls)
	return []ciliumv2.XDSResource{l}
}

// getRouteConfiguration returns the route configuration for the given model.
func (i *SharedIngressTranslator) getRouteConfiguration(m *model.Model) []ciliumv2.XDSResource {
	portHostNameRouteMap := map[string]map[string][]model.HTTPRoute{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			port := "insecure"
			if l.TLS != nil {
				port = "secure"
			}
			if _, ok := portHostNameRouteMap[port]; !ok {
				portHostNameRouteMap[port] = map[string][]model.HTTPRoute{}
			}
			portHostNameRouteMap[port][l.Hostname] = append(portHostNameRouteMap[port][l.Hostname], r)
		}
	}

	var res []ciliumv2.XDSResource
	for port, hostNameRouteMap := range portHostNameRouteMap {
		var virtualhosts []*envoy_config_route_v3.VirtualHost

		// Add HTTPs redirect virtual host for secure host
		if port == insecureHost && i.enforceHTTPs {
			for h, r := range portHostNameRouteMap[secureHost] {
				vhs, _ := translation.NewVirtualHostWithDefaults(h, true, r)
				virtualhosts = append(virtualhosts, vhs)
			}
		}

		for h, r := range hostNameRouteMap {
			vhs, _ := translation.NewVirtualHostWithDefaults(h, false, r)
			virtualhosts = append(virtualhosts, vhs)
		}

		// the route name should match the value in http connection manager
		// otherwise the request will be dropped by envoy
		routeName := fmt.Sprintf("%s-%s-listener-%s", i.namespace, i.name, port)
		rc, _ := translation.NewRouteConfiguration(routeName, virtualhosts)
		res = append(res, rc)
	}
	return res
}

func (i *SharedIngressTranslator) getClusters(m *model.Model) []ciliumv2.XDSResource {
	namespaceNamePortMap := getNamespaceNamePortsMap(m)

	var sortedClusterNames []string
	for ns, v := range namespaceNamePortMap {
		for name, ports := range v {
			for _, port := range ports {
				// the name is having the format of "namespace/name:port"
				sortedClusterNames = append(sortedClusterNames, fmt.Sprintf("%s/%s:%s", ns, name, port))
			}
		}
	}
	sort.Strings(sortedClusterNames)

	res := make([]ciliumv2.XDSResource, 0, len(sortedClusterNames))
	for _, name := range sortedClusterNames {
		c, _ := translation.NewClusterWithDefaults(name)
		res = append(res, c)
	}

	return res
}

// getNamespaceNamePortsMap returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMap(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			for _, be := range r.Backends {
				namePortMap, exist := namespaceNamePortMap[be.Namespace]
				if exist {
					namePortMap[be.Name] = sortAndUnique(append(namePortMap[be.Name], be.Port.GetPort()))
				} else {
					namePortMap = map[string][]string{
						be.Name: {be.Port.GetPort()},
					}
				}
				namespaceNamePortMap[be.Namespace] = namePortMap
			}
		}
	}
	return namespaceNamePortMap
}

func sortAndUnique(arr []string) []string {
	m := map[string]struct{}{}
	for _, s := range arr {
		m[s] = struct{}{}
	}

	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}
