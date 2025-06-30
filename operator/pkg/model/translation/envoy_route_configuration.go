// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	goslices "slices"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/slices"
)

type RouteConfigurationMutator func(*envoy_config_route_v3.RouteConfiguration) *envoy_config_route_v3.RouteConfiguration

// desiredEnvoyHTTPRouteConfiguration returns the route configuration for the given model.
func (i *cecTranslator) desiredEnvoyHTTPRouteConfiguration(m *model.Model) ([]ciliumv2.XDSResource, error) {
	var res []ciliumv2.XDSResource

	type hostnameRedirect struct {
		hostname string
		redirect bool
	}

	portHostNameRedirect := map[string][]hostnameRedirect{}
	hostNamePortRoutes := map[string]map[string][]model.HTTPRoute{}

	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			port := insecureHost
			if l.TLS != nil {
				port = secureHost
			}

			if len(r.Hostnames) == 0 {
				hnr := hostnameRedirect{
					hostname: l.Hostname,
					redirect: l.ForceHTTPtoHTTPSRedirect,
				}
				portHostNameRedirect[port] = append(portHostNameRedirect[port], hnr)
				if _, ok := hostNamePortRoutes[l.Hostname]; !ok {
					hostNamePortRoutes[l.Hostname] = map[string][]model.HTTPRoute{}
				}
				hostNamePortRoutes[l.Hostname][port] = append(hostNamePortRoutes[l.Hostname][port], r)
				continue
			}
			for _, h := range r.Hostnames {
				hnr := hostnameRedirect{
					hostname: h,
					redirect: l.ForceHTTPtoHTTPSRedirect,
				}
				portHostNameRedirect[port] = append(portHostNameRedirect[port], hnr)
				if _, ok := hostNamePortRoutes[h]; !ok {
					hostNamePortRoutes[h] = map[string][]model.HTTPRoute{}
				}
				hostNamePortRoutes[h][port] = append(hostNamePortRoutes[h][port], r)
			}
		}
	}

	for _, port := range []string{insecureHost, secureHost} {
		// the route name should match the value in http connection manager
		// otherwise the request will be dropped by envoy
		routeName := fmt.Sprintf("listener-%s", port)

		hostNames, exists := portHostNameRedirect[port]
		if !exists {
			if port == insecureHost && !m.IsHTTPListenerConfigured() ||
				port == secureHost && !m.IsHTTPSListenerConfigured() {
				continue
			}
			rc, err := routeConfiguration(routeName, nil)
			if err != nil {
				return nil, err
			}
			res = append(res, rc)
			continue
		}
		var virtualhosts []*envoy_config_route_v3.VirtualHost

		redirectedHost := map[string]struct{}{}
		// Add HTTPs redirect virtual host for secure host
		if port == insecureHost {
			for _, h := range slices.Unique(portHostNameRedirect[secureHost]) {
				if h.redirect {
					vhs := i.desiredVirtualHost(hostNamePortRoutes[h.hostname][secureHost], VirtualHostParameter{
						HostNames:     []string{h.hostname},
						HTTPSRedirect: true,
						ListenerPort:  m.HTTP[0].Port,
					})
					virtualhosts = append(virtualhosts, vhs)
					redirectedHost[h.hostname] = struct{}{}
				}
			}
		}
		for _, h := range slices.Unique(hostNames) {
			if port == insecureHost {
				if _, ok := redirectedHost[h.hostname]; ok {
					continue
				}
			}
			routes, exists := hostNamePortRoutes[h.hostname][port]
			if !exists {
				continue
			}
			vhs := i.desiredVirtualHost(routes, VirtualHostParameter{
				HostNames:     []string{h.hostname},
				HTTPSRedirect: false,
				ListenerPort:  m.HTTP[0].Port,
			})
			virtualhosts = append(virtualhosts, vhs)
		}

		goslices.SortStableFunc(virtualhosts, func(a, b *envoy_config_route_v3.VirtualHost) int { return cmp.Compare(a.Name, b.Name) })
		rc, err := routeConfiguration(routeName, virtualhosts)
		if err != nil {
			return nil, err
		}
		res = append(res, rc)
	}

	return res, nil
}

// routeConfiguration returns a new route configuration for a given list of http routes.
func routeConfiguration(name string, virtualhosts []*envoy_config_route_v3.VirtualHost) (ciliumv2.XDSResource, error) {
	routeConfig := &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualhosts,
	}
	return toXdsResource(routeConfig, envoy.RouteTypeURL)
}
