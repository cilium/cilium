// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"github.com/cilium/cilium/operator/pkg/model/translation"
)

// NewSharedIngressTranslator returns a new translator for shared ingress mode.
func NewSharedIngressTranslator(name, namespace, secretsNamespace string, enforceHTTPs bool, idleTimeoutSeconds int) translation.Translator {
	return translation.NewTranslator(name, namespace, secretsNamespace, enforceHTTPs, false, idleTimeoutSeconds)
}
