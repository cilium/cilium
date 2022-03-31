// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package k8s

import (
	"github.com/cilium/cilium/pkg/k8s/types"
)

// Export for testing.
func (c *CNPStatusUpdateContext) UpdateViaAPIServer(cnp *types.SlimCNP, enforcing, ok bool, cnpError error, rev uint64, cnpAnnotations map[string]string) error {
	return c.updateViaAPIServer(cnp, enforcing, ok, cnpError, rev, cnpAnnotations)
}
