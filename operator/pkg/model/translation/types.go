// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// Translator is the interface to take the model and generate required CiliumEnvoyConfig,
// LoadBalancer Service, Endpoint, etc.
//
// Different use cases (e.g. Ingress, Gateway API) can provide its own generation logic.
type Translator interface {
	Translate(model *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error)
}

// CECTranslator is the interface to take the model and generate required CiliumEnvoyConfig.
// It might be used as the base for other Translator implementations.
type CECTranslator interface {
	// Translate translates the model to CiliumEnvoyConfig.
	Translate(namespace string, name string, model *model.Model) (*ciliumv2.CiliumEnvoyConfig, error)
}
