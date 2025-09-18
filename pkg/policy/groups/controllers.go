// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"context"
	"log/slog"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
)

const (
	maxConcurrentUpdates = 4
)

// UpdateCNPInformation  retrieves all the CNP that has currently a derivative
// policy and creates the new derivatives policies with the latest information
// from providers.  To avoid issues with rate-limiting this function will
// execute the addDerivative function with a max number of concurrent calls,
// defined on maxConcurrentUpdates.
func UpdateCNPInformation(logger *slog.Logger, clientset client.Clientset, clusterName string) {
	cnpToUpdate := groupsCNPCache.GetAllCNP()
	sem := make(chan bool, maxConcurrentUpdates)
	for _, cnp := range cnpToUpdate {
		sem <- true
		go func(cnp *cilium_v2.CiliumNetworkPolicy) {
			defer func() { <-sem }()
			// We use the same cache for Clusterwide and Namespaced cilium policies
			if cnp.ObjectMeta.Namespace == "" {
				addDerivativePolicy(context.TODO(), logger, clientset, clusterName, cnp, true)
			} else {
				addDerivativePolicy(context.TODO(), logger, clientset, clusterName, cnp, false)
			}
		}(cnp)
	}
}
