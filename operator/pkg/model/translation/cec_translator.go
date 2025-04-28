// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"maps"
	goslices "slices"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/shortener"
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

type ServiceConfig struct {
	ExternalTrafficPolicy string `json:"external_traffic_policy,omitempty"`
}

type HostNetworkConfig struct {
	Enabled           bool                       `json:"enabled,omitempty"`
	NodeLabelSelector *slim_metav1.LabelSelector `json:"node_label_selector,omitempty"`
}

type IPConfig struct {
	IPv4Enabled bool `json:"ipv4_enabled,omitempty"`
	IPv6Enabled bool `json:"ipv6_enabled,omitempty"`
}

type ListenerConfig struct {
	UseAlpn                  bool `json:"use_alpn,omitempty"`
	UseProxyProtocol         bool `json:"use_proxy_protocol,omitempty"`
	StreamIdleTimeoutSeconds int  `json:"stream_idle_timeout_seconds,omitempty"`
}

type ClusterConfig struct {
	IdleTimeoutSeconds int  `json:"idle_timeout_seconds,omitempty"`
	UseAppProtocol     bool `json:"use_app_protocol,omitempty"`
}

type RouteConfig struct {
	// hostNameSuffixMatch is a flag to control whether the host name suffix match.
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	HostNameSuffixMatch bool `json:"host_name_suffix_match,omitempty"`
}

type OriginalIPDetectionConfig struct {
	UseRemoteAddress  bool   `json:"use_remote_address,omitempty"`
	XFFNumTrustedHops uint32 `json:"xff_num_trusted_hops,omitempty"`
}

type Config struct {
	SecretsNamespace string `json:"secrets_namespace,omitempty"`

	ServiceConfig             ServiceConfig             `json:"service_config"`
	HostNetworkConfig         HostNetworkConfig         `json:"host_network_config"`
	IPConfig                  IPConfig                  `json:"ip_config"`
	ListenerConfig            ListenerConfig            `json:"listener_config"`
	ClusterConfig             ClusterConfig             `json:"cluster_config"`
	RouteConfig               RouteConfig               `json:"route_config"`
	OriginalIPDetectionConfig OriginalIPDetectionConfig `json:"original_ip_detection_config"`
}

// cecTranslator is the translator from model to CiliumEnvoyConfig
//
// This translator is used for shared LB mode.
//   - only one instance of CiliumEnvoyConfig with two listeners (secure and
//     in-secure).
//   - no LB service and endpoint
type cecTranslator struct {
	Config Config
}

// NewCECTranslator returns a new translator
func NewCECTranslator(config Config) CECTranslator {
	return &cecTranslator{
		Config: config,
	}
}

func (i *cecTranslator) Translate(namespace string, name string, model *model.Model) (*ciliumv2.CiliumEnvoyConfig, error) {

	backendServices, err := i.desiredBackendServices(model)
	if err != nil {
		return nil, err
	}

	services, err := i.desiredServicesWithPorts(namespace, name, model)
	if err != nil {
		return nil, err
	}

	resources, err := i.desiredResources(model)
	if err != nil {
		return nil, err
	}

	return &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    i.desiredLabels(model),
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			BackendServices: backendServices,
			Services:        services,
			Resources:       resources,
			NodeSelector:    i.desiredNodeSelector(),
		},
	}, nil
}

func (i *cecTranslator) desiredBackendServices(m *model.Model) ([]*ciliumv2.Service, error) {
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
	return res, nil
}

func (i *cecTranslator) desiredServicesWithPorts(namespace string, name string, m *model.Model) ([]*ciliumv2.ServiceListener, error) {
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
			Name:      shortener.ShortenK8sResourceName(name),
			Ports:     ports,
		},
	}, nil
}

func (i *cecTranslator) desiredResources(m *model.Model) ([]ciliumv2.XDSResource, error) {
	var res []ciliumv2.XDSResource

	listener, err := i.desiredEnvoyListener(m)
	if err != nil {
		return nil, err
	}

	httpRoutes, err := i.desiredEnvoyHTTPRouteConfiguration(m)
	if err != nil {
		return nil, err
	}

	clusters, err := i.desiredEnvoyCluster(m)
	if err != nil {
		return nil, err
	}
	res = append(res, listener...)
	res = append(res, httpRoutes...)
	res = append(res, clusters...)

	return res, nil
}

func (i *cecTranslator) desiredLabels(m *model.Model) map[string]string {
	labels := map[string]string{}
	for _, l := range m.HTTP {
		if l.Gamma {
			labels[k8s.UseOriginalSourceAddressLabel] = "true"
			return labels
		}
	}
	labels[k8s.UseOriginalSourceAddressLabel] = "false"
	return labels
}

func (i *cecTranslator) desiredNodeSelector() *slim_metav1.LabelSelector {
	if !i.Config.HostNetworkConfig.Enabled {
		return nil
	}

	return i.Config.HostNetworkConfig.NodeLabelSelector
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
