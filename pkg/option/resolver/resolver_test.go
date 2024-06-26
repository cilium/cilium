// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

func TestWriteConfigurations(t *testing.T) {
	dir := t.TempDir()

	out := map[string]string{
		"A": "a",
		"B": "b",
	}

	err := WriteConfigurations(context.Background(), dir, out)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range out {
		actual, err := os.ReadFile(filepath.Join(dir, k))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != v {
			t.Fatalf("Unexpected value, wanted %s got %s", v, actual)
		}
	}
}

// Test all the various config sources
// - configmap
// - node annotations
// - label selected CNC
// - specific CNC name
func TestResolveConfigurations(t *testing.T) {
	testNS := "test-ns"
	g := gomega.NewWithT(t)
	clients, _ := k8sClient.NewFakeClientset()

	fakeNode := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodename",
			Labels: map[string]string{"a": "b"},
			Annotations: map[string]string{
				"config.cilium.io/anno-key": "anno-val",
			},
		},
	}
	_, err := clients.CoreV1().Nodes().Create(context.Background(), &fakeNode, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "cm",
		},
		Data: map[string]string{
			"cm-key": "cm-val",
		},
	}
	_, err = clients.CoreV1().ConfigMaps(testNS).Create(context.Background(), &cm, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	selCncAlpha := ciliumv2alpha1.CiliumNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "test-1",
		},
		Spec: ciliumv2alpha1.CiliumNodeConfigSpec{
			Defaults: map[string]string{
				"cnc-key": "cnc-val",
			},
			NodeSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"a": "b"},
			},
		},
	}
	_, err = clients.CiliumV2alpha1().CiliumNodeConfigs(testNS).Create(context.Background(), &selCncAlpha, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	// Selectors CiliumNodeConfig v2
	selCnc := ciliumv2.CiliumNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "test-1-v2",
		},
		Spec: ciliumv2.CiliumNodeConfigSpec{
			Defaults: map[string]string{
				"cnc-key-v2": "cnc-val-v2",
			},
			NodeSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"a": "b"},
			},
		},
	}
	_, err = clients.CiliumV2().CiliumNodeConfigs(testNS).Create(context.Background(), &selCnc, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	nameCncV2alpha1 := ciliumv2alpha1.CiliumNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "specific",
		},
		Spec: ciliumv2alpha1.CiliumNodeConfigSpec{
			Defaults: map[string]string{
				"cnc-key-2": "cnc-val-2",
			},
		},
	}
	_, err = clients.CiliumV2alpha1().CiliumNodeConfigs(testNS).Create(context.Background(), &nameCncV2alpha1, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	nameCnc := ciliumv2.CiliumNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "specific-v2",
		},
		Spec: ciliumv2.CiliumNodeConfigSpec{
			Defaults: map[string]string{
				"cnc-key-2-v2": "cnc-val-2-v2",
			},
		},
	}
	_, err = clients.CiliumV2().CiliumNodeConfigs(testNS).Create(context.Background(), &nameCnc, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	config, err := ResolveConfigurations(context.Background(), clients, "nodename",
		[]ConfigSource{
			{
				Kind:      KindConfigMap,
				Namespace: testNS,
				Name:      "cm",
			},
			{
				Kind:      KindNodeConfig,
				Namespace: testNS,
			},
			{
				Kind: KindNode,
				Name: "nodename",
			},
			{
				Kind:      KindNodeConfig,
				Namespace: testNS,
				Name:      "specific",
			},
			{
				Kind:      KindNodeConfig,
				Namespace: testNS,
				Name:      "specific-v2",
			},
		}, nil, nil)
	sortConfigSources(config)

	g.Expect(err).To(gomega.BeNil())
	g.Expect(config).To(gomega.Equal(map[string]string{
		"cm-key":         "cm-val",
		"anno-key":       "anno-val",
		"cnc-key":        "cnc-val",
		"cnc-key-2":      "cnc-val-2",
		"cnc-key-v2":     "cnc-val-v2",
		"cnc-key-2-v2":   "cnc-val-2-v2",
		"config-sources": "cilium-node-config:test-ns/specific,cilium-node-config:test-ns/specific-v2,cilium-node-config:test-ns/test-1,cilium-node-config:test-ns/test-1-v2,config-map:test-ns/cm,node:nodename",
	}))
}

func TestWithBlockedFields(t *testing.T) {
	testNS := "test-ns"
	g := gomega.NewWithT(t)
	clients, _ := k8sClient.NewFakeClientset()

	fakeNode := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodename",
			Labels: map[string]string{"a": "b"},
			Annotations: map[string]string{
				"config.cilium.io/anno-key": "anno-val",
			},
		},
	}
	_, err := clients.CoreV1().Nodes().Create(context.Background(), &fakeNode, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "cm",
		},
		Data: map[string]string{
			"cm-key": "cm-val",
		},
	}
	_, err = clients.CoreV1().ConfigMaps(testNS).Create(context.Background(), &cm, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	selCnc := ciliumv2alpha1.CiliumNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      "test-1",
		},
		Spec: ciliumv2alpha1.CiliumNodeConfigSpec{
			Defaults: map[string]string{
				"allowed-key": "allowed-val",
				"blocked-key": "blocked-val",
			},
			NodeSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"a": "b"},
			},
		},
	}
	_, err = clients.CiliumV2alpha1().CiliumNodeConfigs(testNS).Create(context.Background(), &selCnc, metav1.CreateOptions{})
	g.Expect(err).To(gomega.BeNil())

	sources := []ConfigSource{
		{
			Kind:      KindConfigMap,
			Namespace: testNS,
			Name:      "cm",
		},
		{
			Kind:      KindNodeConfig,
			Namespace: testNS,
		},
	}

	// Test that only allowed-key is allowed
	config, err := ResolveConfigurations(context.Background(), clients, "nodename",
		sources, []string{"allowed-key"}, nil)
	sortConfigSources(config)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(config).To(gomega.Equal(map[string]string{
		"cm-key":         "cm-val",
		"allowed-key":    "allowed-val",
		"config-sources": "cilium-node-config:test-ns/test-1,config-map:test-ns/cm",
	}))

	// Test that blocked-key is blocked
	// but that the first source is privileged
	config, err = ResolveConfigurations(context.Background(), clients, "nodename",
		sources, nil, []string{"blocked-key", "cm-key"})
	sortConfigSources(config)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(config).To(gomega.Equal(map[string]string{
		"cm-key":         "cm-val",
		"allowed-key":    "allowed-val",
		"config-sources": "cilium-node-config:test-ns/test-1,config-map:test-ns/cm",
	}))

}

func TestReadNodeConfigs(t *testing.T) {
	testNS := "test-ns"

	for _, tc := range []struct {
		name       string
		nodeLabels map[string]string

		// can omit namespace + name, will be synthesized with an order
		confs []ciliumv2.CiliumNodeConfigSpec

		expected map[string]string
	}{
		{
			name:       "one-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
					Defaults: map[string]string{"key-1": "val-1"},
				},
			},
			expected: map[string]string{
				"key-1": "val-1",
			},
		},
		{
			name:       "none-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "c",
						},
					},
					Defaults: map[string]string{"key-1": "val-1"},
				},
			},
			expected: map[string]string{},
		},
		{
			name:       "two-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
					Defaults: map[string]string{
						"key-1": "val-1",
						"key-2": "val-2",
					},
				},
				{
					NodeSelector: &metav1.LabelSelector{}, // empty selector, matches all
					Defaults: map[string]string{
						"key-1": "overridden",
						"key-3": "val-3",
					},
				},
				{
					NodeSelector: nil, // selects nothing
					Defaults: map[string]string{
						"key-4": "val-4",
					},
				},
			},
			expected: map[string]string{
				"key-1": "overridden",
				"key-2": "val-2",
				"key-3": "val-3",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			clients, _ := k8sClient.NewFakeClientset()

			fakeNode := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   tc.name,
					Labels: tc.nodeLabels,
				},
			}
			_, err := clients.CoreV1().Nodes().Create(context.Background(), &fakeNode, metav1.CreateOptions{})
			g.Expect(err).To(gomega.BeNil())

			for i, conf := range tc.confs {
				cnc := ciliumv2.CiliumNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("cco-%d", i),
						Namespace: testNS,
					},
					Spec: conf,
				}
				_, err := clients.CiliumV2().CiliumNodeConfigs(testNS).Create(context.Background(), &cnc, metav1.CreateOptions{})
				g.Expect(err).To(gomega.BeNil())
			}

			configs, _, err := readNodeConfigsAllVersions(context.Background(), clients, tc.name, testNS, "")
			g.Expect(err).To(gomega.BeNil())

			g.Expect(configs).To(gomega.Equal(tc.expected))
		})
	}
}

// TODO remove me when CiliumNodeConfig v2alpha1 will be deprecated
func TestReadNodeConfigsAlpha(t *testing.T) {
	testNS := "test-ns"

	for _, tc := range []struct {
		name       string
		nodeLabels map[string]string

		// can omit namespace + name, will be synthesized with an order
		confs []ciliumv2alpha1.CiliumNodeConfigSpec

		expected map[string]string
	}{
		{
			name:       "one-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2alpha1.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
					Defaults: map[string]string{"key-1": "val-1"},
				},
			},
			expected: map[string]string{
				"key-1": "val-1",
			},
		},
		{
			name:       "none-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2alpha1.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "c",
						},
					},
					Defaults: map[string]string{"key-1": "val-1"},
				},
			},
			expected: map[string]string{},
		},
		{
			name:       "two-matching",
			nodeLabels: map[string]string{"a": "b"},
			confs: []ciliumv2alpha1.CiliumNodeConfigSpec{
				{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
					Defaults: map[string]string{
						"key-1": "val-1",
						"key-2": "val-2",
					},
				},
				{
					NodeSelector: &metav1.LabelSelector{}, // empty selector, matches all
					Defaults: map[string]string{
						"key-1": "overridden",
						"key-3": "val-3",
					},
				},
				{
					NodeSelector: nil, // selects nothing
					Defaults: map[string]string{
						"key-4": "val-4",
					},
				},
			},
			expected: map[string]string{
				"key-1": "overridden",
				"key-2": "val-2",
				"key-3": "val-3",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			clients, _ := k8sClient.NewFakeClientset()

			fakeNode := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   tc.name,
					Labels: tc.nodeLabels,
				},
			}
			_, err := clients.CoreV1().Nodes().Create(context.Background(), &fakeNode, metav1.CreateOptions{})
			g.Expect(err).To(gomega.BeNil())

			for i, conf := range tc.confs {
				cnc := ciliumv2alpha1.CiliumNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("cco-%d", i),
						Namespace: testNS,
					},
					Spec: conf,
				}
				_, err := clients.CiliumV2alpha1().CiliumNodeConfigs(testNS).Create(context.Background(), &cnc, metav1.CreateOptions{})
				g.Expect(err).To(gomega.BeNil())
			}

			configs, _, err := readNodeConfigsAllVersions(context.Background(), clients, tc.name, testNS, "")
			g.Expect(err).To(gomega.BeNil())

			g.Expect(configs).To(gomega.Equal(tc.expected))

		})
	}
}

func sortConfigSources(config map[string]string) {
	csSorted := strings.Split(config["config-sources"], ",")
	sort.Strings(csSorted)
	config["config-sources"] = strings.Join(csSorted, ",")
}
