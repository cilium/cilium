// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	gatewayL4ConfigPrefix = "cilium-gateway-l4-"
)

type l4BackendKey struct {
	namespace string
	name      string
	port      uint32
}

var _ GL4CTranslator = (*gl4cTranslator)(nil)

type gl4cTranslator struct{}

// NewGL4CTranslator returns a new translator for CiliumGatewayL4Config.
func NewGL4CTranslator() GL4CTranslator {
	return &gl4cTranslator{}
}

func (g *gl4cTranslator) Translate(namespace string, name string, model *model.Model) (*ciliumv2alpha1.CiliumGatewayL4Config, error) {
	if model == nil || len(model.L4) == 0 {
		return nil, nil
	}

	source, err := l4Source(model.L4)
	if err != nil {
		return nil, err
	}

	gatewayNamespace := source.Namespace
	if gatewayNamespace == "" {
		gatewayNamespace = namespace
	}

	spec := ciliumv2alpha1.CiliumGatewayL4ConfigSpec{
		GatewayRef: ciliumv2alpha1.CiliumGatewayReference{
			Name:      source.Name,
			Namespace: gatewayNamespace,
		},
		Listeners: g.desiredListeners(model.L4, gatewayNamespace),
	}

	return &ciliumv2alpha1.CiliumGatewayL4Config{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gatewayL4ConfigName(source.Name),
			Namespace: gatewayNamespace,
		},
		Spec: spec,
	}, nil
}

func (g *gl4cTranslator) desiredListeners(listeners []model.L4Listener, gatewayNamespace string) []ciliumv2alpha1.CiliumGatewayL4Listener {
	res := make([]ciliumv2alpha1.CiliumGatewayL4Listener, 0, len(listeners))
	for _, listener := range listeners {
		res = append(res, ciliumv2alpha1.CiliumGatewayL4Listener{
			Name:     listener.Name,
			Protocol: ciliumv2alpha1.L4ProtocolType(listener.Protocol),
			Port:     listener.Port,
			Backends: g.desiredBackends(listener, gatewayNamespace),
		})
	}
	return res
}

func (g *gl4cTranslator) desiredBackends(listener model.L4Listener, gatewayNamespace string) []ciliumv2alpha1.CiliumGatewayL4Backend {
	weightByBackend := map[l4BackendKey]uint16{}
	for _, route := range listener.Routes {
		for _, be := range route.Backends {
			key, weight, ok := g.backendKeyAndWeight(be, gatewayNamespace)
			if !ok {
				continue
			}
			weightByBackend[key] = weight
		}
	}

	keys := sortedBackendKeys(weightByBackend)
	backends := make([]ciliumv2alpha1.CiliumGatewayL4Backend, 0, len(keys))
	for _, key := range keys {
		weight := weightByBackend[key]
		backends = append(backends, ciliumv2alpha1.CiliumGatewayL4Backend{
			Name:      key.name,
			Namespace: key.namespace,
			Port:      key.port,
			Weight:    ptr.To(weight),
		})
	}
	return backends
}

func (g *gl4cTranslator) backendKeyAndWeight(be model.Backend, gatewayNamespace string) (l4BackendKey, uint16, bool) {
	if be.Port == nil || be.Port.Port == 0 {
		return l4BackendKey{}, 0, false
	}

	weight := uint16(loadbalancer.DefaultBackendWeight)
	if be.Weight != nil {
		// don't process backend with weight 0
		if *be.Weight == 0 {
			return l4BackendKey{}, 0, false
		}
		weight = uint16(*be.Weight)
	}

	ns := gatewayNamespace
	if be.Namespace != "" {
		ns = be.Namespace
	}
	return l4BackendKey{namespace: ns, name: be.Name, port: be.Port.Port}, weight, true
}

func sortedBackendKeys(backendWeights map[l4BackendKey]uint16) []l4BackendKey {
	keys := make([]l4BackendKey, 0, len(backendWeights))
	for key := range backendWeights {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b l4BackendKey) int {
		if a.namespace != b.namespace {
			return cmp.Compare(a.namespace, b.namespace)
		}
		if a.name != b.name {
			return cmp.Compare(a.name, b.name)
		}
		return cmp.Compare(a.port, b.port)
	})
	return keys
}

func gatewayL4ConfigName(gatewayName string) string {
	return shortener.ShortenK8sResourceName(gatewayL4ConfigPrefix + gatewayName)
}

func l4Source(listeners []model.L4Listener) (model.FullyQualifiedResource, error) {
	if len(listeners) == 0 {
		return model.FullyQualifiedResource{}, fmt.Errorf("l4 listeners can't be empty")
	}
	listener := listeners[0]
	if len(listener.Sources) == 0 {
		return model.FullyQualifiedResource{}, fmt.Errorf("l4 listener source can't be empty")
	}
	source := listener.Sources[0]
	if source.Name == "" {
		return model.FullyQualifiedResource{}, fmt.Errorf("l4 listener source name can't be empty")
	}
	return source, nil
}
