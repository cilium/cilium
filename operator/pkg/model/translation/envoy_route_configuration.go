// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	goslices "slices"
	"strconv"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/slices"
)

// RouteConfigurationMutator transforms a RouteConfiguration before serialization.
type RouteConfigurationMutator func(*envoy_config_route_v3.RouteConfiguration) *envoy_config_route_v3.RouteConfiguration

// desiredEnvoyHTTPRouteConfiguration returns the route configuration for the given model.
func (i *cecTranslator) desiredEnvoyHTTPRouteConfiguration(m *model.Model) ([]ciliumv2.XDSResource, error) {
	var res []ciliumv2.XDSResource
	allAuthFilters := i.getUniqueAuthFilters(m)
	allExtProcFilters := i.getUniqueExtProcFilters(m)

	type hostnameRedirect struct {
		hostname string
		redirect bool
	}

	portHostNameRedirect := map[string][]hostnameRedirect{}
	hostNamePortRoutes := map[string]map[string][]model.HTTPRoute{}

	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			port := insecureHost
			if len(l.TLS) > 0 {
				if m.NeedsPerPortListeners() {
					port = fmt.Sprintf("%d", l.Port)
				} else {
					port = secureHost
				}
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

	// Collect all port keys in a deterministic order.
	allPorts := make([]string, 0, len(portHostNameRedirect))
	for p := range portHostNameRedirect {
		allPorts = append(allPorts, p)
	}
	goslices.Sort(allPorts)

	// Also emit an empty RouteConfiguration for configured ports with no routes.
	if !goslices.Contains(allPorts, insecureHost) && m.IsHTTPListenerConfigured() {
		allPorts = append([]string{insecureHost}, allPorts...)
	}
	for _, httpsPort := range httpsPortKeys(m) {
		if !goslices.Contains(allPorts, httpsPort) {
			allPorts = append(allPorts, httpsPort)
		}
	}
	goslices.SortFunc(allPorts, func(a, b string) int {
		// "insecure" always sorts first to preserve backward-compatible ordering.
		if a == insecureHost {
			return -1
		}
		if b == insecureHost {
			return 1
		}
		return cmp.Compare(a, b)
	})

	for _, port := range allPorts {
		// the route name should match the value in http connection manager
		// otherwise the request will be dropped by envoy
		routeName := fmt.Sprintf("listener-%s", port)

		hostNames, exists := portHostNameRedirect[port]
		if !exists {
			if port == insecureHost {
				if !m.IsHTTPListenerConfigured() {
					continue
				}
			} else if port == secureHost {
				// Legacy single-HTTPS-port mode.
				if !m.IsHTTPSListenerConfigured() {
					continue
				}
			} else {
				// per-port mode: skip if no HTTPS listener uses this port.
				if !m.IsHTTPSPortConfigured(parseUint32(port)) {
					continue
				}
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
		// Add HTTPS redirect virtual hosts across all configured HTTPS ports.
		if port == insecureHost {
			for _, httpsPort := range httpsPortKeys(m) {
				for _, h := range slices.Unique(portHostNameRedirect[httpsPort]) {
					if h.redirect {
						if _, already := redirectedHost[h.hostname]; already {
							continue
						}
						redirectedHost[h.hostname] = struct{}{}
						vhs := i.desiredVirtualHost(hostNamePortRoutes[h.hostname][httpsPort], VirtualHostParameter{
							HostNames:         []string{h.hostname},
							HTTPSRedirect:     true,
							ListenerPort:      m.HTTP[0].Port,
							AllAuthFilters:    allAuthFilters,
							AllExtProcFilters: allExtProcFilters,
						})
						virtualhosts = append(virtualhosts, vhs)
					}
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
				HostNames:         []string{h.hostname},
				HTTPSRedirect:     false,
				ListenerPort:      m.HTTP[0].Port,
				AllAuthFilters:    allAuthFilters,
				AllExtProcFilters: allExtProcFilters,
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

// httpsPortKeys returns sorted, unique port strings for all HTTPS listeners in the model.
func httpsPortKeys(m *model.Model) []string {
	if !m.NeedsPerPortListeners() {
		// No per-port splitting needed: use the legacy "secure" key for the HTTPS port.
		if m.IsHTTPSListenerConfigured() {
			return []string{secureHost}
		}
		return nil
	}
	seen := map[string]struct{}{}
	for _, l := range m.HTTP {
		if len(l.TLS) > 0 {
			seen[fmt.Sprintf("%d", l.Port)] = struct{}{}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	goslices.Sort(keys)
	return keys
}

// parseUint32 parses a base-10 uint32 string. The callers only pass strings
// produced by fmt.Sprintf("%d", l.Port) where l.Port is already a uint32, so
// parse failure is not possible in practice; zero is returned on error.
func parseUint32(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

// routeConfiguration returns a new route configuration for a given list of http routes.
func routeConfiguration(name string, virtualhosts []*envoy_config_route_v3.VirtualHost) (ciliumv2.XDSResource, error) {
	routeConfig := &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualhosts,
	}
	return toXdsResource(routeConfig, envoy.RouteTypeURL)
}
