// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"
)

func toYaml(t *testing.T, obj any) string {
	t.Helper()

	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}

func readInputDir(t *testing.T, dir string) []client.Object {
	t.Helper()

	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var res []client.Object
	for _, file := range files {
		if !file.IsDir() {
			filePath := fmt.Sprintf("%s/%s", dir, file.Name())
			if strings.HasPrefix(file.Name(), "httproute") {
				obj := &gatewayv1.HTTPRoute{}
				readInput(t, filePath, obj)
				res = append(res, obj)
				continue
			}

			if strings.HasPrefix(file.Name(), "service") {
				obj := &corev1.Service{}
				readInput(t, filePath, obj)
				res = append(res, obj)
				continue
			}
		}
	}

	return res
}

func readInput(t *testing.T, file string, obj any) {
	t.Helper()

	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	t.Helper()

	// unmarshal and marshal to prevent formatting diffs
	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(yamlText)
}
