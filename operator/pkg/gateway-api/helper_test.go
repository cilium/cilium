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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	k8syaml "sigs.k8s.io/yaml"
)

func fromYaml(t *testing.T, yamlText string, obj any) {
	t.Helper()

	require.NoError(t, k8syaml.Unmarshal([]byte(yamlText), obj))
}

func toYaml(t *testing.T, obj any) string {
	t.Helper()

	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}

func getResourceKind(yamlStr string) (string, string, error) {
	var meta metav1.TypeMeta
	err := k8syaml.Unmarshal([]byte(yamlStr), &meta)
	if err != nil {
		return "", "", err
	}
	return meta.APIVersion, meta.Kind, nil
}

func readInputDir(t *testing.T, dir string) []client.Object {
	t.Helper()

	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var res []client.Object
	for _, file := range files {
		if !file.IsDir() {
			filePath := fmt.Sprintf("%s/%s", dir, file.Name())
			res = append(res, readInput(t, filePath)...)
		}
	}

	return res
}

func readInput(t *testing.T, file string) []client.Object {
	t.Helper()

	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	var res []client.Object
	for o := range strings.SplitSeq(string(inputYaml), "\n---\n") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		_, kind, err := getResourceKind(o)
		require.NoError(t, err, "failed to get resource kind from input YAML")
		switch kind {
		case "Namespace":
			obj := &corev1.Namespace{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "Service":
			obj := &corev1.Service{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "ConfigMap":
			obj := &corev1.ConfigMap{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "Secret":
			obj := &corev1.Secret{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "HTTPRoute":
			obj := &gatewayv1.HTTPRoute{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "TLSRoute":
			obj := &gatewayv1alpha2.TLSRoute{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "GRPCRoute":
			obj := &gatewayv1.GRPCRoute{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "Gateway":
			obj := &gatewayv1.Gateway{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "GatewayClass":
			obj := &gatewayv1.GatewayClass{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "ReferenceGrant":
			obj := &gatewayv1beta1.ReferenceGrant{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "ServiceImport":
			obj := &mcsapiv1alpha1.ServiceImport{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		case "BackendTLSPolicy":
			obj := &gatewayv1.BackendTLSPolicy{}
			fromYaml(t, o, obj)
			res = append(res, obj)
		}
	}

	return res
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
