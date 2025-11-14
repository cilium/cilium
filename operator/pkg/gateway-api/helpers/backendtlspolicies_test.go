// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
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

	fixtureTwoTargetsSameNameDiffSectionName := gatewayv1.BackendTLSPolicy{
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
					SectionName: ptr.To[gatewayv1.SectionName]("https1"),
				},
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "service-one",
					},
					SectionName: ptr.To[gatewayv1.SectionName]("https2"),
				},
			},
		},
	}

	fixtureOneServiceWithSectionName := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "one-with-section-name",
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
					SectionName: ptr.To[gatewayv1.SectionName]("https1"),
				},
			},
		},
	}

	fixtureTwoServiceWithSectionName := gatewayv1.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: btlspAPIVersion,
			Kind:       btlspKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "one-with-section-name-2",
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
					SectionName: ptr.To[gatewayv1.SectionName]("https1"),
				},
			},
		},
	}

	fixtureServiceOneFullName := types.NamespacedName{
		Namespace: "default",
		Name:      "service-one",
	}

	fixtureServiceTwoFullName := types.NamespacedName{
		Namespace: "default",
		Name:      "service-two",
	}

	tests := []struct {
		name      string
		btlspList *gatewayv1.BackendTLSPolicyList
		want      BackendTLSPolicyServiceMap
	}{
		{
			name:      "Empty list",
			btlspList: &gatewayv1.BackendTLSPolicyList{},
			want:      BackendTLSPolicyServiceMap{},
		},
		{
			name: "Single entry, single target",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureOneService,
				},
			},
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureOneService,
					},
				},
			},
		},
		{
			name: "Single entry, two targets",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoServices,
				},
			},
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureTwoServices,
					},
				},
				fixtureServiceTwoFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureTwoServices,
					},
				},
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
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureOneService,
					},
					Conflicted: map[types.NamespacedName]*gatewayv1.BackendTLSPolicy{
						{
							Name:      fixtureOneServiceNew.Name,
							Namespace: fixtureOneServiceNew.Namespace,
						}: &fixtureOneServiceNew,
					},
				},
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
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureOneService,
					},
					Conflicted: map[types.NamespacedName]*gatewayv1.BackendTLSPolicy{
						{
							Name:      fixtureOneServiceNew.Name,
							Namespace: fixtureOneServiceNew.Namespace,
						}: &fixtureOneServiceNew,
					},
				},
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
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureOneService,
					},
					Conflicted: map[types.NamespacedName]*gatewayv1.BackendTLSPolicy{
						{
							Name:      fixtureOneServiceSameTime.GetName(),
							Namespace: fixtureOneServiceSameTime.GetNamespace(),
						}: &fixtureOneServiceSameTime,
					},
				},
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
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureOneService,
					},
					Conflicted: map[types.NamespacedName]*gatewayv1.BackendTLSPolicy{
						{
							Name:      fixtureOneServiceSameTime.GetName(),
							Namespace: fixtureOneServiceSameTime.GetNamespace(),
						}: &fixtureOneServiceSameTime,
					},
				},
			},
		},
		{
			name: "Single entry, two targets with same name",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoServicesSameName,
				},
			},
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName(""): &fixtureTwoServicesSameName,
					},
				},
			},
		},
		{
			name: "Single entry, two targets with same target, different section name",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoTargetsSameNameDiffSectionName,
				},
			},
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName("https1"): &fixtureTwoTargetsSameNameDiffSectionName,
						gatewayv1.SectionName("https2"): &fixtureTwoTargetsSameNameDiffSectionName,
					},
				},
			},
		},
		{
			name: "multiple entries, one target, different section name",
			btlspList: &gatewayv1.BackendTLSPolicyList{
				Items: []gatewayv1.BackendTLSPolicy{
					fixtureTwoServiceWithSectionName,
					fixtureOneServiceWithSectionName,
				},
			},
			want: BackendTLSPolicyServiceMap{
				fixtureServiceOneFullName: &BackendTLSPolicyTargetServiceCollection{
					Valid: map[gatewayv1.SectionName]*gatewayv1.BackendTLSPolicy{
						gatewayv1.SectionName("https1"): &fixtureOneServiceWithSectionName,
					},
					Conflicted: map[types.NamespacedName]*gatewayv1.BackendTLSPolicy{
						{
							Name:      fixtureTwoServiceWithSectionName.GetName(),
							Namespace: fixtureTwoServiceWithSectionName.GetNamespace(),
						}: &fixtureTwoServiceWithSectionName,
					},
				},
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
