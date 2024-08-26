// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/annotation"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option/resolver"
)

const key = "key"

func TestGetPriorityForKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		overrides resolver.ConfigOverride
		index     int
		sourceLen int
		expected  int
	}{
		{
			name:      "no_overrides",
			key:       key,
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{}, DenyConfigKeys: []string{}},
			index:     0,
			sourceLen: 5,
			expected:  5,
		},
		{
			name:      "key_in_allow",
			key:       key,
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{key}, DenyConfigKeys: []string{}},
			index:     2,
			sourceLen: 5,
			expected:  3, // sourceLen - index
		},
		{
			name:      "key_not_in_allow",
			key:       "key2",
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{key}, DenyConfigKeys: []string{}},
			index:     2,
			sourceLen: 5,
			expected:  7, // sourceLen + index
		},
		{
			name:      "key_in_deny",
			key:       key,
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{}, DenyConfigKeys: []string{key}},
			index:     1,
			sourceLen: 5,
			expected:  6, // sourceLen + index
		},
		{
			name:      "key_not_in_deny",
			key:       key,
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{}, DenyConfigKeys: []string{"key2"}},
			index:     1,
			sourceLen: 5,
			expected:  4, // sourceLen - index
		},
		{
			name:      "allow_has_precedence_over_deny",
			key:       key,
			overrides: resolver.ConfigOverride{AllowConfigKeys: []string{key}, DenyConfigKeys: []string{key}},
			index:     1,
			sourceLen: 5,
			expected:  4, // sourceLen - index, allow is considered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getPriorityForKey(tt.key, tt.overrides, tt.index, tt.sourceLen)
			if actual != tt.expected {
				t.Errorf("getPriorityForKey(%s, %v, %d, %d) = %d; expected %d", tt.key, tt.overrides, tt.index, tt.sourceLen, actual, tt.expected)
			}
		})
	}
}

func TestParseNodeConfig(t *testing.T) {
	tests := []struct {
		name string
		node *corev1.Node
		want map[string]string
	}{
		{
			name: "valid_labels_annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						annotation.ConfigPrefix + "/key1": "value1",
					},
					Annotations: map[string]string{
						annotation.ConfigPrefix + "/key2": "value2",
					},
				},
			},
			want: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name: "invalid_annotation_format",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"invalidkey": "value",
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "invalid_config_key",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"prefix/invalid/key": "value",
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "valid_and_invalid_annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						annotation.ConfigPrefix + "/key1": "value1",
						"invalidkey":                      "value2",
						"prefix/invalid/key":              "value3",
					},
				},
			},
			want: map[string]string{
				"key1": "value1",
			},
		},
		{
			name: "no_relevant_annotations_or_labels",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"some/label": "value"},
					Annotations: map[string]string{"some/annotation": "value"},
				},
			},
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(logging.SlogNopHandler)
			got := parseNodeConfig(tt.node, logger)

			if len(got) != len(tt.want) {
				t.Errorf("parseNodeConfig() got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseNodeConfig() got[%v] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}
