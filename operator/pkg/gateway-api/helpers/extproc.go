// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// FindExtProcFilter returns the CiliumEnvoyExtProcFilter matching the given
// namespace and name from filters, or nil if no match exists.
func FindExtProcFilter(filters []v2alpha1.CiliumEnvoyExtProcFilter, namespace, name string) *v2alpha1.CiliumEnvoyExtProcFilter {
	for i := range filters {
		if filters[i].Namespace == namespace && filters[i].Name == name {
			return &filters[i]
		}
	}
	return nil
}
