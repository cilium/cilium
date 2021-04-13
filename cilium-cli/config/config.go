// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium-cli/defaults"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	_, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
	}
	if err = k.restartPodsUponConfigChange(params); err != nil {
		return err
	}

	return nil
}

func (k *K8sConfig) Delete(ctx context.Context, key string, params Parameters) error {
	patch := []byte(`[{"op": "remove", "path": "/data/` + key + `"}]`)

	k.Log("✨ Removing key %s from ConfigMap %s...", key, defaults.ConfigMapName)
	_, err := k.client.PatchConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with patch %q: %w", defaults.ConfigMapName, patch, err)
	}
	if err = k.restartPodsUponConfigChange(params); err != nil {
		return err
	}

	return nil
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

func (k *K8sConfig) restartPodsUponConfigChange(params Parameters) error {
	if !params.Restart {
		fmt.Println("⚠️  Restart Cilium pods for configmap changes to take effect")
		return nil
	}
	if err := k.client.DeletePodCollection(context.Background(), params.Namespace,
		metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: defaults.CiliumPodSelector}); err != nil {
		return fmt.Errorf("⚠️  unable to restart Cilium pods: %v", err)
	} else {
		fmt.Println("♻️  Restarted Cilium pods")
	}

	return nil
}
