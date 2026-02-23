/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import v1 "sigs.k8s.io/gateway-api/apis/v1"

type LocalPolicyTargetReference v1.LocalPolicyTargetReference

type NamespacedPolicyTargetReference v1.NamespacedPolicyTargetReference

type LocalPolicyTargetReferenceWithSectionName v1.LocalPolicyTargetReferenceWithSectionName

type PolicyConditionType v1.PolicyConditionType

type PolicyConditionReason v1.PolicyConditionReason

type PolicyAncestorStatus v1.PolicyAncestorStatus

type PolicyStatus v1.PolicyStatus
