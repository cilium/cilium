// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	apivalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option/resolver"
)

const (
	metadataName = "metadata.name="
)

func NewConfigMapReflector(cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig], c config, l *slog.Logger) []k8s.ReflectorConfig[DynamicConfig] {
	if !cs.IsEnabled() || !c.EnableDynamicConfig {
		return []k8s.ReflectorConfig[DynamicConfig]{}
	}
	sources, overrides, err := parseConfigs(c)
	if err != nil {
		l.Error("Failed to process configs", logfields.Error, err)
		return []k8s.ReflectorConfig[DynamicConfig]{}
	}

	var reflectors = make([]k8s.ReflectorConfig[DynamicConfig], 0, len(sources))
	sLen := len(sources)
	for i, source := range sources {

		var reflector k8s.ReflectorConfig[DynamicConfig]
		switch source.Kind {
		case resolver.KindConfigMap:
			reflector = configMapReflector(source.Name, source.Namespace, cs, t, i, sLen, overrides)
		case resolver.KindNodeConfig:
			reflector = ciliumNodeConfigReflector(source.Name, source.Namespace, cs, t, i, sLen, overrides)
		case resolver.KindNode:
			reflector = ciliumNodeReflector(source.Name, cs, t, l, i, sLen, overrides)
		}

		reflectors = append(reflectors, reflector)
	}

	return reflectors
}

func parseConfigs(c config) ([]resolver.ConfigSource, resolver.ConfigOverride, error) {
	var sources []resolver.ConfigSource
	if err := json.Unmarshal([]byte(c.ConfigSources), &sources); err != nil {
		return nil, resolver.ConfigOverride{}, fmt.Errorf("error during unmarshall config-sources: %w", err)
	}

	var overrides resolver.ConfigOverride
	if err := json.Unmarshal([]byte(c.ConfigSourcesOverrides), &overrides); err != nil {
		return nil, resolver.ConfigOverride{}, fmt.Errorf("error during unmarshall config-sources: %w", err)
	}
	return sources, overrides, nil
}

func getPriorityForKey(key string, overrides resolver.ConfigOverride, index int, sourceLen int) int {
	// The first source have no restriction for overrides
	if index == 0 {
		return sourceLen
	}

	// If the len(AllowConfigKeys) > 0, DenyConfigKeys should be ignored
	if len(overrides.AllowConfigKeys) > 0 {
		if slices.Contains(overrides.AllowConfigKeys, key) {
			return sourceLen - index
		}
		return sourceLen + index
	}

	// If the AllowConfigKeys is empty, check DenyConfigKeys
	if len(overrides.DenyConfigKeys) > 0 && slices.Contains(overrides.DenyConfigKeys, key) {
		return sourceLen + index
	}

	return sourceLen - index
}

func configMapReflector(name string, namespace string, cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig], index int, sourceLen int, overrides resolver.ConfigOverride) k8s.ReflectorConfig[DynamicConfig] {
	return k8s.ReflectorConfig[DynamicConfig]{
		Name:  "cm-" + name + "-" + namespace,
		Table: t,
		TransformMany: func(o any) []DynamicConfig {
			cm := o.(*v1.ConfigMap).DeepCopy()
			var entries = make([]DynamicConfig, 0, len(cm.Data))
			for k, v := range cm.Data {
				priority := getPriorityForKey(k, overrides, index, sourceLen)
				dc := DynamicConfig{Key: Key{Name: k, Source: cm.Name}, Value: v, Priority: priority}
				entries = append(entries, dc)
			}
			return entries
		},
		ListerWatcher: utils.ListerWatcherWithModifiers(
			utils.ListerWatcherFromTyped[*v1.ConfigMapList](cs.CoreV1().ConfigMaps(namespace)),
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.ParseSelectorOrDie(metadataName + name).String()
			},
		),
		QueryAll: func(txn statedb.ReadTxn, t statedb.Table[DynamicConfig]) iter.Seq2[DynamicConfig, statedb.Revision] {
			return statedb.Filter(
				t.All(txn),
				func(dc DynamicConfig) bool {
					return dc.Key.Source == name
				},
			)
		},
	}
}
func ciliumNodeConfigReflector(name string, namespace string, cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig], index int, sourceLen int, overrides resolver.ConfigOverride) k8s.ReflectorConfig[DynamicConfig] {
	return k8s.ReflectorConfig[DynamicConfig]{
		Name:  "cnc-" + name + "-" + namespace,
		Table: t,
		TransformMany: func(o any) []DynamicConfig {
			cnc := o.(*ciliumv2.CiliumNodeConfig).DeepCopy()
			var entries = make([]DynamicConfig, 0, len(cnc.Spec.Defaults))
			for k, v := range cnc.Spec.Defaults {
				priority := getPriorityForKey(k, overrides, index, sourceLen)
				dc := DynamicConfig{Key: Key{Name: k, Source: cnc.Name}, Value: v, Priority: priority}
				entries = append(entries, dc)
			}
			return entries
		},
		ListerWatcher: utils.ListerWatcherWithModifiers(
			utils.ListerWatcherFromTyped[*ciliumv2.CiliumNodeConfigList](cs.CiliumV2().CiliumNodeConfigs(namespace)),
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.ParseSelectorOrDie(metadataName + name).String()
			},
		),
		QueryAll: func(txn statedb.ReadTxn, t statedb.Table[DynamicConfig]) iter.Seq2[DynamicConfig, statedb.Revision] {
			return statedb.Filter(
				t.All(txn),
				func(dc DynamicConfig) bool {
					return dc.Key.Source == name
				},
			)
		},
	}
}

func ciliumNodeReflector(name string, cs k8sClient.Clientset, t statedb.RWTable[DynamicConfig], l *slog.Logger, index int, sourceLen int, overrides resolver.ConfigOverride) k8s.ReflectorConfig[DynamicConfig] {
	return k8s.ReflectorConfig[DynamicConfig]{
		Name:  "node-" + name,
		Table: t,
		TransformMany: func(o any) []DynamicConfig {
			var entries []DynamicConfig
			node := o.(*corev1.Node).DeepCopy()

			for k, v := range parseNodeConfig(node, l) {
				priority := getPriorityForKey(k, overrides, index, sourceLen)
				dc := DynamicConfig{Key: Key{Name: k, Source: node.Name}, Value: v, Priority: priority}
				entries = append(entries, dc)
			}
			return entries
		},
		ListerWatcher: utils.ListerWatcherWithModifiers(
			utils.ListerWatcherFromTyped[*corev1.NodeList](cs.Slim().CoreV1().Nodes()),
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.ParseSelectorOrDie(metadataName + name).String()
			},
		),
		QueryAll: func(txn statedb.ReadTxn, t statedb.Table[DynamicConfig]) iter.Seq2[DynamicConfig, statedb.Revision] {
			return statedb.Filter(
				t.All(txn),
				func(dc DynamicConfig) bool {
					return dc.Key.Source == name
				},
			)
		},
	}
}

// parseNodeConfig returns a map of overridable fields from the Node object
// It allows annotation or labels with config.cilium.io/K=V
func parseNodeConfig(node *corev1.Node, logger *slog.Logger) map[string]string {
	out := map[string]string{}
	read := func(in map[string]string) {
		for k, v := range in {
			if !strings.HasPrefix(k, annotation.ConfigPrefix) {
				continue
			}

			s := strings.SplitN(k, "/", 2)
			if len(s) != 2 {
				logger.Warn("Detected invalid format in annotation, expected config.cilium.io/KEY=VALUE. Skipping", logfields.ConfigAnnotation, k)
				continue
			}
			key := s[1]
			if errs := apivalidation.IsConfigMapKey(key); len(errs) > 0 {
				logger.Warn("Detected invalid key. Skipping", logfields.ConfigAnnotation, k, logfields.Error, errs)
				continue
			}
			out[key] = v
		}
	}

	read(node.Labels)
	read(node.Annotations)
	return out
}
