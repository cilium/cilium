// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_buildBackendTLSPolicyLookup(t *testing.T) {
	btlspAPIVersion := gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version
	btlspKind := "BackendTLSPolicy"

	now := metav1.NewTime(time.Now())
	oneHourAgo := metav1.NewTime(time.Now().Add(-1 * time.Hour))

	fixtureOneService := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "one",
			Namespace:         "default",
			CreationTimestamp: oneHourAgo,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
			},
		},
	}

	fixtureOneServiceSameTime := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "one-sametime",
			Namespace:         "default",
			CreationTimestamp: oneHourAgo,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
			},
		},
	}

	fixtureOneServiceNew := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "one-new",
			Namespace:         "default",
			CreationTimestamp: now,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
			},
		},
	}

	fixtureTwoServices := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "two",
			Namespace: "default",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-two",
					},
				},
			},
		},
	}

	// There's no real reason to do this, but we should handle it anyway.
	fixtureTwoServicesSameName := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "two",
			Namespace: "default",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
				},
			},
		},
	}
	tests := []struct {
		name      string
		btlspList *gatewayv1.BackendTLSPolicyList
		want      map[string]gatewayv1.BackendTLSPolicy
	}{
		{
			name:      "Empty list",
			btlspList: &gatewayv1.BackendTLSPolicyList{},
			want:      map[string]gatewayv1.BackendTLSPolicy{},
		},
		{
			name: "Single entry, single target",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneService,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureOneService,
			},
		},
		{
			name: "Single entry, two targets",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoServices,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureTwoServices,
				"default/service-two": fixtureTwoServices,
			},
		},
		{
			name: "multiple entries, one target, one older",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneServiceNew,
					fixtureOneService,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureOneService,
			},
		},
		{
			name: "multiple entries, one target, one older, diff order",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneService,
					fixtureOneServiceNew,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureOneService,
			},
		},
		{
			name: "multiple entries, one target, same time",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneServiceSameTime,
					fixtureOneService,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureOneService,
			},
		},
		{
			name: "multiple entries, one target, same time, diff order",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneService,
					fixtureOneServiceSameTime,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureOneService,
			},
		},
		{
			name: "Single entry, two targets with same name",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoServicesSameName,
				},
			},
			want: map[string]gatewayv1.BackendTLSPolicy{
				"default/service-one": fixtureTwoServicesSameName,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildBackendTLSPolicyLookup(tt.btlspList)
			gotDiff := cmp.Diff(got, tt.want)
			if gotDiff != "" {
				t.Errorf("buildBackendTLSPolicyLookup():\n%s", gotDiff)
			}
		})
	}
}
