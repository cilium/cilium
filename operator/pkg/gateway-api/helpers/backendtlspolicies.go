// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// BackendTLSPolicyTargetServiceCollection holds all the
// BackendTLSPolicy objects that targetRef Service, including
// which ones are valid and which conflicted.
//
// This is required because BackendTLSPolicy objects can:
// * target multiple Services
// * target the same Service, with different ports
//
// And, multiple BackendTLSPolicies can also do the same.
//
// Gateway API conflict resolution rules dictate that, when
// two BackendTLSPolicies target the same Service, the precedence
// goes, continuing on ties:
//
// 1. Oldest BackendTLSPolicy, by creation time
// 2. First BackendTLSPolicy, lexigraphically sorted.
//
// The BackendTLSPolicyTargetServiceCollection struct holds details
// about which are the Valid (chosen) policies, and which are Conflicted.
// This is then used by the status-setting functions to figure out
// what status to set.
type BackendTLSPolicyTargetServiceCollection struct {
	// Valid holds the map of the section name on the Service
	// to the relevant BackendTLSPolicy.
	//
	// Note that the an empty value for SectionName means
	// "all sections", and will conflict with any other section name.
	Valid map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy
	// Conflicted holds the all the conflicted BackendTLSPolicies that
	// target this Service, with the map key being the object's full name.
	// This avoids traversing a slice to find a match all the time.
	Conflicted map[types.NamespacedName]*gatewayv1.BackendTLSPolicy
}

func (b *BackendTLSPolicyTargetServiceCollection) UpsertValidPolicy(sectionName gatewayv1.SectionName, btlsp *gatewayv1.BackendTLSPolicy) {
	if b.Valid == nil {
		b.Valid = make(map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy)
	}

	b.Valid[sectionName] = btlsp
}

func (b *BackendTLSPolicyTargetServiceCollection) UpsertConflictedPolicy(btlspFullName types.NamespacedName, btlsp *gatewayv1.BackendTLSPolicy) {
	if b.Conflicted == nil {
		b.Conflicted = make(map[types.NamespacedName]*gatewayv1.BackendTLSPolicy)
	}

	b.Conflicted[btlspFullName] = btlsp
}

// BackendTLSPolicyServiceMap is a lookup map that tracks valid and invalid BackendTLSPolicies
// by the relevant targetRef service full name.
type BackendTLSPolicyServiceMap map[types.NamespacedName]*BackendTLSPolicyTargetServiceCollection

// BuildBackendTLSPolicyLookup builds a lookup map of BackendTLSPolicy by the NamespacedName of referenced
// backend Services. These are deduplicated using the Gateway API conflict resolution rules (oldest wins, then
// first lexicographically wins).
func BuildBackendTLSPolicyLookup(btlspList *gatewayv1.BackendTLSPolicyList) BackendTLSPolicyServiceMap {
	lookupMap := make(BackendTLSPolicyServiceMap)

	for _, currentBTLSP := range btlspList.Items {
		for _, targetRef := range currentBTLSP.Spec.TargetRefs {
			if !IsServiceTargetRef(targetRef) {
				continue
			}

			svcName := types.NamespacedName{
				Name:      string(targetRef.Name),
				Namespace: currentBTLSP.GetNamespace(),
			}

			var sectionName gatewayv1.SectionName = ""

			if targetRef.SectionName != nil {
				sectionName = *targetRef.SectionName
			}

			existingCollection, ok := lookupMap[svcName]
			if !ok {
				// If the targetRef isn't there, we add it, and then add this policy as valid.
				lookupMap[svcName] = &BackendTLSPolicyTargetServiceCollection{}
				lookupMap[svcName].UpsertValidPolicy(sectionName, &currentBTLSP)
				continue
			}

			// The targetRef exists, so we see if there is a valid entry for this section name.
			existingBTLSP, ok := existingCollection.Valid[sectionName]
			if !ok {
				// There's no entry for this section name, so we create one and continue.
				existingCollection.UpsertValidPolicy(sectionName, &currentBTLSP)
				continue
			}

			// Get the full names of everything
			currentName := client.ObjectKeyFromObject(&currentBTLSP)
			existingName := client.ObjectKeyFromObject(existingBTLSP)

			if currentName == existingName {
				// We will only get here if there are multiple references to the same Service in the same Policy,
				// with the same section name. In this case, we shouldn't do anything.
				continue
			}

			// There is already a valid entry for this section name, so now we check timestamps.
			if currentBTLSP.ObjectMeta.CreationTimestamp.Before(&existingBTLSP.ObjectMeta.CreationTimestamp) {
				// if the current policy has an older creation time, it wins
				// Move the existing policy into the Conflicted map
				lookupMap[svcName].UpsertConflictedPolicy(existingName, existingBTLSP)
				// Upsert the current BTLSP into the Valid set.
				lookupMap[svcName].UpsertValidPolicy(sectionName, &currentBTLSP)
				continue
			}

			if existingBTLSP.ObjectMeta.CreationTimestamp.Before(&currentBTLSP.ObjectMeta.CreationTimestamp) {
				// if the existing policy has an older creation time, it wins
				// Move the current policy into the Conflicted map
				lookupMap[svcName].UpsertConflictedPolicy(currentName, &currentBTLSP)
				// The existing BTLSP is already in the Valid set, nothing more to do.
				continue
			}

			// If the creation timestamps are equal, because neither are before the other,
			// and they're not the same object, then the lexicographically first one wins.
			if currentName.String() < existingName.String() {
				// Move the existing policy into the Conflicted map
				lookupMap[svcName].UpsertConflictedPolicy(existingName, existingBTLSP)
				// Upsert the current BTLSP into the Valid set.
				lookupMap[svcName].UpsertValidPolicy(sectionName, &currentBTLSP)
				continue
			}

			// Otherwise, the current policy is conflicted.
			lookupMap[svcName].UpsertConflictedPolicy(currentName, &currentBTLSP)
		}
	}
	return lookupMap
}
