// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

type k8sConfigImplementation interface {
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	PatchConfigMap(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.ConfigMap, error)
	DeletePodCollection(ctx context.Context, namespace string, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
}

type K8sConfig struct {
	client k8sConfigImplementation
	params Parameters
}

type Parameters struct {
	Namespace string
	Restart   bool
	Writer    io.Writer
}

func NewK8sConfig(client k8sConfigImplementation, p Parameters) *K8sConfig {
	return &K8sConfig{
		client: client,
		params: p,
	}
}

func (k *K8sConfig) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sConfig) Set(ctx context.Context, key, value string, params Parameters) error {
	patch := []byte(`{"data":{"` + key + `":"` + value + `"}}`)

	k.Log("✨ Patching ConfigMap %s with %s=%s...", defaults.ConfigMapName, key, value)

	if _, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName,
		types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
	}

	return k.restartPodsUponConfigChange(ctx, params)
}

func (k *K8sConfig) Delete(ctx context.Context, key string, params Parameters) error {
	patch := []byte(`[{"op": "remove", "path": "/data/` + key + `"}]`)

	k.Log("✨ Removing key %s from ConfigMap %s...", key, defaults.ConfigMapName)

	if _, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName,
		types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
	}

	return k.restartPodsUponConfigChange(ctx, params)
}

func (k *K8sConfig) View(ctx context.Context) (string, error) {
	var buf bytes.Buffer

	w := tabwriter.NewWriter(&buf, 0, 0, 4, ' ', 0)

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable get ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	keys := make([]string, 0, len(cm.Data))
	for k := range cm.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fmt.Fprintf(w, key+"\t"+cm.Data[key]+"\n")
	}

	w.Flush()

	return buf.String(), nil
}

func (k *K8sConfig) restartPodsUponConfigChange(ctx context.Context, params Parameters) error {
	if !params.Restart {
		fmt.Println("⚠️  Restart Cilium pods for configmap changes to take effect")
		return nil
	}

	if err := k.client.DeletePodCollection(ctx, params.Namespace,
		metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector}); err != nil {
		return fmt.Errorf("⚠️  unable to restart Cilium pods: %v", err)
	}

	fmt.Println("♻️  Restarted Cilium pods")

	return nil
}
