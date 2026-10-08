// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIsPodStoreOutdatedForUID(t *testing.T) {
	storeUID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	otherUID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	tests := []struct {
		name string
		uid  string
		pod  *slim_corev1.Pod
		want bool
	}{
		{
			name: "empty uid never outdated",
			uid:  "",
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid match not outdated",
			uid:  storeUID,
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid mismatch without mirror annotation is outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
				},
			},
			want: true,
		},
		{
			name: "uid mismatch mirror pod not outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
					Annotations: map[string]string{
						corev1.MirrorPodAnnotationKey: otherUID,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPodStoreOutdatedForUID(tt.uid, tt.pod)
			require.Equal(t, tt.want, got)
		})
	}
}
