// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	}

	for _, listener := range model.L4 {
		backendWeights := map[l4BackendKey]int32{}
		for _, route := range listener.Routes {
			for _, be := range route.Backends {
				if be.Port == nil || be.Port.Port == 0 {
					continue
				}

				weight := int32(1)
				if be.Weight != nil {
					weight = *be.Weight
				}
				if weight <= 0 {
					continue
				}

				ns := be.Namespace
				if ns == "" {
					ns = gatewayNamespace
				}
				key := l4BackendKey{namespace: ns, name: be.Name, port: be.Port.Port}
				if prev, ok := backendWeights[key]; ok && prev >= weight {
					continue
				}
				backendWeights[key] = weight
			}
		}

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

		backends := make([]ciliumv2alpha1.CiliumGatewayL4Backend, 0, len(keys))
		for _, key := range keys {
			weight := backendWeights[key]
			backends = append(backends, ciliumv2alpha1.CiliumGatewayL4Backend{
				Name:      key.name,
				Namespace: key.namespace,
				Port:      int32(key.port),
				Weight:    ptr.To(weight),
			})
		}

		spec.Listeners = append(spec.Listeners, ciliumv2alpha1.CiliumGatewayL4Listener{
			Name:     listener.Name,
			Protocol: ciliumv2alpha1.L4ProtocolType(listener.Protocol),
			Port:     int32(listener.Port),
			Backends: backends,
		})
	}

	return &ciliumv2alpha1.CiliumGatewayL4Config{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gatewayL4ConfigName(source.Name),
			Namespace: gatewayNamespace,
		},
		Spec: spec,
	}, nil
}

func gatewayL4ConfigName(gatewayName string) string {
	return shortener.ShortenK8sResourceName(gatewayL4ConfigPrefix + gatewayName)
}

func resourceAPIVersion(resource model.FullyQualifiedResource) string {
	if resource.Group == "" {
		return resource.Version
	}
	return resource.Group + "/" + resource.Version
}

func l4Source(listeners []model.L4Listener) (model.FullyQualifiedResource, error) {
	for _, listener := range listeners {
		if len(listener.Sources) == 0 {
			return model.FullyQualifiedResource{}, fmt.Errorf("l4 listener source can't be empty")
		}
		source := listener.Sources[0]
		if source.Name == "" {
			return model.FullyQualifiedResource{}, fmt.Errorf("l4 listener source name can't be empty")
		}
		return source, nil
	}
	return model.FullyQualifiedResource{}, fmt.Errorf("l4 listeners can't be empty")
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	maps.Copy(left, right)
	return left
}
