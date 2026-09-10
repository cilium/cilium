// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1_test

import (
	"encoding/json"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
)

func TestCiliumEnvoyExtProcFilterSchema(t *testing.T) {
	validator := newCiliumEnvoyExtProcFilterValidator(t)

	t.Run("messageTimeout", func(t *testing.T) {
		tests := map[string]struct {
			value string
			valid bool
		}{
			"banana":            {value: "banana"},
			"negative":          {value: "-5s"},
			"fractional":        {value: "1.5s"},
			"microseconds":      {value: "100us"},
			"bare zero":         {value: "0"},
			"empty":             {value: ""},
			"zero seconds":      {value: "0s", valid: true},
			"milliseconds":      {value: "500ms", valid: true},
			"one hour":          {value: "1h", valid: true},
			"compound duration": {value: "1h30m", valid: true},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				err := validateCiliumEnvoyExtProcFilter(validator, &tc.value, nil)
				if tc.valid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("backendRef.namespace", func(t *testing.T) {
		validNamespace := "backend-namespace"
		emptyNamespace := ""
		uppercaseNamespace := "Backend"
		trailingHyphenNamespace := "backend-"
		longNamespace := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

		tests := map[string]struct {
			value *string
			valid bool
		}{
			"omitted":         {valid: true},
			"valid":           {value: &validNamespace, valid: true},
			"empty":           {value: &emptyNamespace},
			"uppercase":       {value: &uppercaseNamespace},
			"trailing hyphen": {value: &trailingHyphenNamespace},
			"64 characters":   {value: &longNamespace},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				err := validateCiliumEnvoyExtProcFilter(validator, nil, tc.value)
				if tc.valid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	})
}

func TestCiliumEnvoyExtProcFilterMessageTimeoutCELRule(t *testing.T) {
	crd := client.GetPregeneratedCRD(hivetest.Logger(t), client.CEEPFCRDName)
	schema := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	specSchema, ok := schema.Properties["spec"]
	require.True(t, ok)
	timeoutSchema, ok := specSchema.Properties["messageTimeout"]
	require.True(t, ok)

	const expectedRule = "duration(self) <= duration('1h')"
	const expectedMessage = "messageTimeout must not exceed 1h"
	for _, rule := range timeoutSchema.XValidations {
		if rule.Rule == expectedRule && rule.Message == expectedMessage {
			return
		}
	}
	t.Fatalf("messageTimeout schema does not contain %q", expectedRule)
}

func newCiliumEnvoyExtProcFilterValidator(t *testing.T) validation.SchemaCreateValidator {
	t.Helper()

	crd := client.GetPregeneratedCRD(hivetest.Logger(t), client.CEEPFCRDName)
	schemaJSON, err := json.Marshal(crd.Spec.Versions[0].Schema)
	require.NoError(t, err)

	var crv apiextensionsv1.CustomResourceValidation
	require.NoError(t, json.Unmarshal(schemaJSON, &crv))

	var internal apiextensionsinternal.CustomResourceValidation
	require.NoError(t, apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(&crv, &internal, nil))

	validator, _, err := validation.NewSchemaValidator(internal.OpenAPIV3Schema)
	require.NoError(t, err)
	return validator
}

func validateCiliumEnvoyExtProcFilter(validator validation.SchemaCreateValidator, messageTimeout, namespace *string) error {
	backendRef := map[string]any{
		"name": "ext-proc-service",
		"port": int64(50051),
	}
	if namespace != nil {
		backendRef["namespace"] = *namespace
	}

	spec := map[string]any{
		"backendRef": backendRef,
	}
	if messageTimeout != nil {
		spec["messageTimeout"] = *messageTimeout
	}

	object := &unstructured.Unstructured{}
	objectJSON, err := yaml.Marshal(map[string]any{
		"apiVersion": "cilium.io/v2alpha1",
		"kind":       "CiliumEnvoyExtProcFilter",
		"metadata": map[string]any{
			"name":      "example",
			"namespace": "default",
		},
		"spec": spec,
	})
	if err != nil {
		return err
	}
	objectJSON, err = yaml.YAMLToJSON(objectJSON)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(objectJSON, object); err != nil {
		return err
	}

	if errs := validation.ValidateCustomResource(nil, object, validator); len(errs) > 0 {
		return errs.ToAggregate()
	}
	return nil
}
