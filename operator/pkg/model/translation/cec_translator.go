// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"maps"
	goslices "slices"
	"sort"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/slices"
)

const (
	secureHost   = "secure"
	insecureHost = "insecure"

	AppProtocolH2C = "kubernetes.io/h2c"
	AppProtocolWS  = "kubernetes.io/ws"
	AppProtocolWSS = "kubernetes.io/wss"
)

var _ CECTranslator = (*cecTranslator)(nil)

// cecTranslator is the translator from model to CiliumEnvoyConfig
//
// This translator is used for shared LB mode.
//   - only one instance of CiliumEnvoyConfig with two listeners (secure and
//     in-secure).
//   - no LB service and endpoint
type cecTranslator struct {
	secretsNamespace string
	useProxyProtocol bool
	useAppProtocol   bool
	useAlpn          bool

	hostNetworkEnabled           bool
	hostNetworkNodeLabelSelector *slim_metav1.LabelSelector
	ipv4Enabled                  bool
	ipv6Enabled                  bool

	// hostNameSuffixMatch is a flag to control whether the host name suffix match.
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	hostNameSuffixMatch bool

	idleTimeoutSeconds int

	xffNumTrustedHops uint32
}

// NewCECTranslator returns a new translator
func NewCECTranslator(secretsNamespace string, useProxyProtocol bool, useAppProtocol bool, hostNameSuffixMatch bool, idleTimeoutSeconds int,
	hostNetworkEnabled bool, hostNetworkNodeLabelSelector *slim_metav1.LabelSelector, ipv4Enabled bool, ipv6Enabled bool,
	xffNumTrustedHops uint32,
) CECTranslator {
	return &cecTranslator{
		secretsNamespace:             secretsNamespace,
		useProxyProtocol:             useProxyProtocol,
		useAppProtocol:               useAppProtocol,
		useAlpn:                      false,
		hostNameSuffixMatch:          hostNameSuffixMatch,
		idleTimeoutSeconds:           idleTimeoutSeconds,
		xffNumTrustedHops:            xffNumTrustedHops,
		hostNetworkEnabled:           hostNetworkEnabled,
		hostNetworkNodeLabelSelector: hostNetworkNodeLabelSelector,
		ipv4Enabled:                  ipv4Enabled,
		ipv6Enabled:                  ipv6Enabled,
	}
}

func (i *cecTranslator) WithUseAlpn(useAlpn bool) {
	i.useAlpn = useAlpn
}

func (i *cecTranslator) Translate(namespace string, name string, model *model.Model) (*ciliumv2.CiliumEnvoyConfig, error) {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				k8s.UseOriginalSourceAddressLabel: "false",
			},
		},
	}

	cec.Spec.BackendServices = i.getBackendServices(model)
	cec.Spec.Services = i.getServicesWithPorts(namespace, name, model)
	cec.Spec.Resources = i.getResources(model)

	if i.hostNetworkEnabled {
		cec.Spec.NodeSelector = i.hostNetworkNodeLabelSelector
	}

	return cec, nil
}

func (i *cecTranslator) getBackendServices(m *model.Model) []*ciliumv2.Service {
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

func (i *cecTranslator) getServicesWithPorts(namespace string, name string, m *model.Model) []*ciliumv2.ServiceListener {
	// Find all the ports used in the model and build a set of them
	allPorts := make(map[uint16]struct{})

	for _, hl := range m.HTTP {
		if _, ok := allPorts[uint16(hl.Port)]; !ok {
			allPorts[uint16(hl.Port)] = struct{}{}
		}
	}
	for _, tlsl := range m.TLSPassthrough {
		if _, ok := allPorts[uint16(tlsl.Port)]; !ok {
			allPorts[uint16(tlsl.Port)] = struct{}{}
		}
	}

	// ensure the ports are stably sorted
	ports := goslices.Sorted(maps.Keys(allPorts))

	return []*ciliumv2.ServiceListener{
		{
			Namespace: namespace,
			Name:      model.Shorten(name),
			Ports:     ports,
		},
	}
}

func (i *cecTranslator) getResources(m *model.Model) []ciliumv2.XDSResource {
	var res []ciliumv2.XDSResource

	res = append(res, i.getListener(m)...)
	res = append(res, i.getEnvoyHTTPRouteConfiguration(m)...)
	res = append(res, i.getClusters(m)...)

	return res
}

func tlsSecretsToHostnames(httpListeners []model.HTTPListener) map[model.TLSSecret][]string {
	tlsSecretsToHostnames := make(map[model.TLSSecret][]string)
	for _, h := range httpListeners {
		for _, s := range h.TLS {
			tlsSecretsToHostnames[s] = append(tlsSecretsToHostnames[s], h.Hostname)
		}
	}

	return tlsSecretsToHostnames
}

func tlsPassthroughBackendsToHostnames(tlsPassthroughListeners []model.TLSPassthroughListener) map[string][]string {
	tlsPassthroughBackendsToHostnames := make(map[string][]string)
	for _, h := range tlsPassthroughListeners {
		for _, route := range h.Routes {
			for _, backend := range route.Backends {
				key := fmt.Sprintf("%s:%s:%s", backend.Namespace, backend.Name, backend.Port.GetPort())
				tlsPassthroughBackendsToHostnames[key] = append(tlsPassthroughBackendsToHostnames[key], route.Hostnames...)
			}
		}
	}

	return tlsPassthroughBackendsToHostnames
}

// getListener returns the listener for the given model.
// - HTTP non-TLS filters
// - HTTP TLS filters
// - TLS passthrough filters
func (i *cecTranslator) getListener(m *model.Model) []ciliumv2.XDSResource {
	if len(m.HTTP) == 0 && len(m.TLSPassthrough) == 0 {
		return nil
	}

	mutatorFuncs := []ListenerMutator{}
	if i.useProxyProtocol {
		mutatorFuncs = append(mutatorFuncs, WithProxyProtocol())
	}

	if i.useAlpn {
		mutatorFuncs = append(mutatorFuncs, WithAlpn())
	}

	if i.hostNetworkEnabled {
		mutatorFuncs = append(mutatorFuncs, WithHostNetworkPort(m, i.ipv4Enabled, i.ipv6Enabled))
	}

	if i.xffNumTrustedHops > 0 {
		mutatorFuncs = append(mutatorFuncs, WithXffNumTrustedHops(i.xffNumTrustedHops))
	}

	l, _ := newListenerWithDefaults("listener", i.secretsNamespace, len(m.HTTP) > 0, tlsSecretsToHostnames(m.HTTP), tlsPassthroughBackendsToHostnames(m.TLSPassthrough), mutatorFuncs...)
	return []ciliumv2.XDSResource{l}
}

// getRouteConfiguration returns the route configuration for the given model.
func (i *cecTranslator) getEnvoyHTTPRouteConfiguration(m *model.Model) []ciliumv2.XDSResource {
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
		hostNames, exists := portHostNameRedirect[port]
		if !exists {
			continue
		}
		var virtualhosts []*envoy_config_route_v3.VirtualHost

		redirectedHost := map[string]struct{}{}
		// Add HTTPs redirect virtual host for secure host
		if port == insecureHost {
			for _, h := range slices.Unique(portHostNameRedirect[secureHost]) {
				if h.redirect {
					vhs, _ := NewVirtualHostWithDefaults(hostNamePortRoutes[h.hostname][secureHost], VirtualHostParameter{
						HostNames:           []string{h.hostname},
						HTTPSRedirect:       true,
						HostNameSuffixMatch: i.hostNameSuffixMatch,
						ListenerPort:        m.HTTP[0].Port,
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
			vhs, _ := NewVirtualHostWithDefaults(routes, VirtualHostParameter{
				HostNames:           []string{h.hostname},
				HTTPSRedirect:       false,
				HostNameSuffixMatch: i.hostNameSuffixMatch,
				ListenerPort:        m.HTTP[0].Port,
			})
			virtualhosts = append(virtualhosts, vhs)
		}

		// the route name should match the value in http connection manager
		// otherwise the request will be dropped by envoy
		routeName := fmt.Sprintf("listener-%s", port)
		goslices.SortStableFunc(virtualhosts, func(a, b *envoy_config_route_v3.VirtualHost) int { return cmp.Compare(a.Name, b.Name) })
		rc, _ := NewRouteConfiguration(routeName, virtualhosts)
		res = append(res, rc)
	}

	return res
}

func getClusterName(ns, name, port string) string {
	// the name is having the format of "namespace:name:port"
	// -> slash would prevent ParseResources from rewriting with CEC namespace and name!
	return fmt.Sprintf("%s:%s:%s", ns, name, port)
}

func getClusterServiceName(ns, name, port string) string {
	// the name is having the format of "namespace/name:port"
	return fmt.Sprintf("%s/%s:%s", ns, name, port)
}

func (i *cecTranslator) getClusters(m *model.Model) []ciliumv2.XDSResource {
	envoyClusters := map[string]ciliumv2.XDSResource{}
	var sortedClusterNames []string

	for ns, v := range getNamespaceNamePortsMapForHTTP(m) {
		for name, ports := range v {
			for _, port := range ports {
				clusterName := getClusterName(ns, name, port)
				clusterServiceName := getClusterServiceName(ns, name, port)
				sortedClusterNames = append(sortedClusterNames, clusterName)
				mutators := []ClusterMutator{
					WithConnectionTimeout(5),
					WithIdleTimeout(i.idleTimeoutSeconds),
					WithClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_ROUND_ROBIN)),
					WithOutlierDetection(true),
				}

				if isGRPCService(m, ns, name, port) {
					mutators = append(mutators, WithProtocol(HTTPVersion2))
				} else if i.useAppProtocol {
					appProtocol := getAppProtocol(m, ns, name, port)

					switch appProtocol {
					case AppProtocolH2C:
						mutators = append(mutators, WithProtocol(HTTPVersion2))
					default:
						// When --use-app-protocol is used, envoy will set upstream protocol to HTTP/1.1
						mutators = append(mutators, WithProtocol(HTTPVersion1))
					}
				}
				envoyClusters[clusterName], _ = NewHTTPCluster(clusterName, clusterServiceName, mutators...)
			}
		}
	}
	for ns, v := range getNamespaceNamePortsMapForTLS(m) {
		for name, ports := range v {
			for _, port := range ports {
				clusterName := getClusterName(ns, name, port)
				clusterServiceName := getClusterServiceName(ns, name, port)
				sortedClusterNames = append(sortedClusterNames, clusterName)
				envoyClusters[clusterName], _ = NewTCPClusterWithDefaults(clusterName, clusterServiceName)
			}
		}
	}

	goslices.Sort(sortedClusterNames)
	res := make([]ciliumv2.XDSResource, len(sortedClusterNames))
	for i, name := range sortedClusterNames {
		res[i] = envoyClusters[name]
	}

	return res
}

func isGRPCService(m *model.Model, ns string, name string, port string) bool {
	var res bool

	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			if !r.IsGRPC {
				continue
			}
			for _, be := range r.Backends {
				if be.Name == name && be.Namespace == ns && be.Port != nil && be.Port.GetPort() == port {
					return true
				}
			}
		}
	}
	return res
}

func getAppProtocol(m *model.Model, ns string, name string, port string) string {
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			for _, be := range r.Backends {
				if be.Name == name && be.Namespace == ns && be.Port != nil && be.Port.GetPort() == port {
					if be.AppProtocol != nil {
						return *be.AppProtocol
					}
				}
			}
		}
	}

	return ""
}

// getNamespaceNamePortsMap returns a map of namespace -> name -> ports.
// it gets all HTTP and TLS routes.
// The ports are sorted and unique.
func getNamespaceNamePortsMap(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			for _, be := range r.Backends {
				namePortMap, exist := namespaceNamePortMap[be.Namespace]
				if exist {
					namePortMap[be.Name] = slices.SortedUnique(append(namePortMap[be.Name], be.Port.GetPort()))
				} else {
					namePortMap = map[string][]string{
						be.Name: {be.Port.GetPort()},
					}
				}
				namespaceNamePortMap[be.Namespace] = namePortMap
			}
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)

			for _, rm := range r.RequestMirrors {
				if rm.Backend == nil {
					continue
				}
				mergeBackendsInNamespaceNamePortMap([]model.Backend{*rm.Backend}, namespaceNamePortMap)
			}
		}
	}

	for _, l := range m.TLSPassthrough {
		for _, r := range l.Routes {
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)
		}
	}

	return namespaceNamePortMap
}

// getNamespaceNamePortsMapForHTTP returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMapForHTTP(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)
			for _, rm := range r.RequestMirrors {
				if rm.Backend == nil {
					continue
				}
				mergeBackendsInNamespaceNamePortMap([]model.Backend{*rm.Backend}, namespaceNamePortMap)
			}
		}
	}
	return namespaceNamePortMap
}

// getNamespaceNamePortsMapFroTLS returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMapForTLS(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.TLSPassthrough {
		for _, r := range l.Routes {
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)
		}
	}
	return namespaceNamePortMap
}

func mergeBackendsInNamespaceNamePortMap(backends []model.Backend, namespaceNamePortMap map[string]map[string][]string) {
	for _, be := range backends {
		namePortMap, exist := namespaceNamePortMap[be.Namespace]
		if exist {
			namePortMap[be.Name] = slices.SortedUnique(append(namePortMap[be.Name], be.Port.GetPort()))
		} else {
			namePortMap = map[string][]string{
				be.Name: {be.Port.GetPort()},
			}
		}
		namespaceNamePortMap[be.Namespace] = namePortMap
	}
}
