// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sconstv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sconstv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestCreateCRDUpdatesEndpointWorkloadSchema(t *testing.T) {
	tests := []struct {
		name              string
		versionedName     string
		resourceName      string
		workloadFieldPath []string
	}{
		{
			name:              "CiliumEndpoint",
			versionedName:     CEPCRDName,
			resourceName:      k8sconstv2.CEPName,
			workloadFieldPath: []string{"status", "workload"},
		},
		{
			name:              "CiliumEndpointSlice",
			versionedName:     CESCRDName,
			resourceName:      k8sconstv2alpha1.CESName,
			workloadFieldPath: []string{"endpoints", "items", "workload"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			target := constructV1CRD(tt.resourceName, GetPregeneratedCRD(logger, tt.versionedName))
			targetWorkload := requireCRDSchemaProperty(t, target, tt.workloadFieldPath...)
			require.Contains(t, targetWorkload.Properties, "name")
			require.Contains(t, targetWorkload.Properties, "kind")

			installed := target.DeepCopy()
			installed.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey] = "1.34.4"
			installedSchema := removeCRDSchemaProperty(
				*installed.Spec.Versions[0].Schema.OpenAPIV3Schema,
				tt.workloadFieldPath,
			)
			installed.Spec.Versions[0].Schema.OpenAPIV3Schema = &installedSchema
			requireNoCRDSchemaProperty(t, installed, tt.workloadFieldPath...)
			installed.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{{
				Type:   apiextensionsv1.Established,
				Status: apiextensionsv1.ConditionTrue,
			}}

			client := fake.NewSimpleClientset(installed)
			updated, err := createCRD(t.Context(), logger, client, tt.versionedName, tt.resourceName)
			require.NoError(t, err)
			require.Equal(
				t,
				k8sconst.CustomResourceDefinitionSchemaVersion,
				updated.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey],
			)
			updatedWorkload := requireCRDSchemaProperty(t, updated, tt.workloadFieldPath...)
			require.Contains(t, updatedWorkload.Properties, "name")
			require.Contains(t, updatedWorkload.Properties, "kind")
		})
	}
}

func removeCRDSchemaProperty(schema apiextensionsv1.JSONSchemaProps, path []string) apiextensionsv1.JSONSchemaProps {
	if len(path) == 1 {
		delete(schema.Properties, path[0])
		return schema
	}

	property := schema.Properties[path[0]]
	if path[0] == "items" {
		property = *schema.Items.Schema
		property = removeCRDSchemaProperty(property, path[1:])
		schema.Items.Schema = &property
		return schema
	}

	property = removeCRDSchemaProperty(property, path[1:])
	schema.Properties[path[0]] = property
	return schema
}

func crdSchemaProperty(crd *apiextensionsv1.CustomResourceDefinition, path ...string) (*apiextensionsv1.JSONSchemaProps, bool) {
	schema := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	for _, field := range path {
		if field == "items" {
			if schema.Items == nil || schema.Items.Schema == nil {
				return nil, false
			}
			schema = schema.Items.Schema
			continue
		}

		property, ok := schema.Properties[field]
		if !ok {
			return nil, false
		}
		schema = &property
	}
	return schema, true
}

func requireCRDSchemaProperty(t *testing.T, crd *apiextensionsv1.CustomResourceDefinition, path ...string) *apiextensionsv1.JSONSchemaProps {
	t.Helper()

	schema, ok := crdSchemaProperty(crd, path...)
	require.Truef(t, ok, "schema field %q is missing", path)
	return schema
}

func requireNoCRDSchemaProperty(t *testing.T, crd *apiextensionsv1.CustomResourceDefinition, path ...string) {
	t.Helper()

	_, ok := crdSchemaProperty(crd, path...)
	require.Falsef(t, ok, "schema field %q is present", path)
}
