// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// Contains types and utilities to read in BackendTLSPolicy objects plus relevant data from YAML
// then munge it into the correct data structure for the ingestion process to read.
//
// Unfortunate, but unavoidable because the types for BackendTLSPolicy need to use maps extensively,
// which are hard to represent correctly in YAML.

type BackendTLSPolicyMapEntry struct {
	ServiceName   string                                 `json:"svcName,omitempty"`
	ValidPolicies map[string]*gatewayv1.BackendTLSPolicy `json:"valid,omitempty"`
}

type BackendTLSPolicyMapFixture struct {
	Policies []BackendTLSPolicyMapEntry `json:"policies,omitempty"`
}

func (bm *BackendTLSPolicyMapFixture) ToBackendTLSPolicyMap() (helpers.BackendTLSPolicyServiceMap, error) {
	btlspMap := make(helpers.BackendTLSPolicyServiceMap)

	for _, fixture := range bm.Policies {
		svcNameSplit := strings.Split(fixture.ServiceName, "/")
		if len(svcNameSplit) != 2 {
			return nil, fmt.Errorf("Service Name must consist of namespace/name, was %s", fixture.ServiceName)
		}
		svcFullName := types.NamespacedName{Namespace: svcNameSplit[0], Name: svcNameSplit[1]}
		for sn, policy := range fixture.ValidPolicies {
			sectionName := gatewayv1.SectionName(sn)
			// If there's no service entry in the btlspMap already, add one
			if _, ok := btlspMap[svcFullName]; !ok {
				btlspMap[svcFullName] = &helpers.BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						sectionName: policy,
					},
				}
				continue
			}
			// If there's already a sectionName entry, that's an error
			if _, ok := btlspMap[svcFullName].Valid[sectionName]; ok {
				return nil, fmt.Errorf("Can't have multiple identical sectionNames, got %s twice", sectionName)
			}
			btlspMap[svcFullName].Valid[sectionName] = policy
		}
	}
	return btlspMap, nil
}
