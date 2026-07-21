// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"log/slog"
	"sync"

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sYaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	crdSchemas []func(logger *slog.Logger) []apiextensionsv1.CustomResourceDefinition

	crdSchemaValidatorsOnce sync.Once
	crdSchemaValidators     map[schema.GroupVersionKind]validation.SchemaCreateValidator
)

func init() {
	RegisterCRDSchemas(ciliumCRDs)
}

func ciliumCRDs(logger *slog.Logger) []apiextensionsv1.CustomResourceDefinition {
	list := client.CustomResourceDefinitionList()
	crds := make([]apiextensionsv1.CustomResourceDefinition, 0, len(list))
	for _, crdList := range list {
		crds = append(crds, client.GetPregeneratedCRD(logger, crdList.Name))
	}
	return crds
}

// RegisterCRDSchemas adds CRDs for [ValidateCRD] to validate against. Call it
// from an init(), as the CRDs are read on the first validation. Their kinds
// have to be in [Scheme] too, since the validation decodes them.
func RegisterCRDSchemas(crds func(logger *slog.Logger) []apiextensionsv1.CustomResourceDefinition) {
	crdSchemas = append(crdSchemas, crds)
}

func getCRDSchemaValidators(logger *slog.Logger) map[schema.GroupVersionKind]validation.SchemaCreateValidator {
	crdSchemaValidatorsOnce.Do(func() {
		crdSchemaValidators = make(map[schema.GroupVersionKind]validation.SchemaCreateValidator)
		for _, crds := range crdSchemas {
			for _, crd := range crds(logger) {
				for _, version := range crd.Spec.Versions {
					if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
						continue
					}
					v, err := schemaValidatorFor(version.Schema)
					if err != nil {
						// Skip this schema so the other CRDs can still be
						// validated.
						logger.Warn("Skipping CRD schema validator",
							logfields.CRDName, crd.Name,
							logfields.Version, version.Name,
							logfields.Error, err)
						continue
					}
					gvk := schema.GroupVersionKind{
						Group:   crd.Spec.Group,
						Version: version.Name,
						Kind:    crd.Spec.Names.Kind,
					}
					crdSchemaValidators[gvk] = v
				}
			}
		}
	})
	return crdSchemaValidators
}

func schemaValidatorFor(crv *apiextensionsv1.CustomResourceValidation) (validation.SchemaCreateValidator, error) {
	var crvInternal apiextensionsinternal.CustomResourceValidation
	if err := apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		crv, &crvInternal, nil,
	); err != nil {
		return nil, err
	}

	v, _, err := validation.NewSchemaValidator(crvInternal.OpenAPIV3Schema)
	return v, err
}

// ValidateCRD validates a raw CRD YAML document against the embedded CRD
// schemas, like the kube-apiserver does. Kinds without a known CRD schema are
// accepted as-is.
//
// With schemaValidation the document is validated against the CRD OpenAPI
// schema. Unknown fields are rejected either way, as a typo is never
// intentional.
//
// The input must be the raw YAML and not a decoded object, since the typed
// decode drops the unknown fields we want to catch.
func ValidateCRD(logger *slog.Logger, rawYAML []byte, schemaValidation bool) error {
	var us unstructured.Unstructured
	if err := k8sYaml.Unmarshal(rawYAML, &us); err != nil {
		return fmt.Errorf("decoding into unstructured: %w", err)
	}

	validator, ok := getCRDSchemaValidators(logger)[us.GroupVersionKind()]
	if !ok {
		return nil
	}

	// Reject unknown fields before the schema check, as a typo otherwise
	// shows up as the correct field missing.
	//
	// This is stricter than the apiserver, which prunes unknown fields
	// instead of rejecting them. We want to catch typos.
	if _, _, err := StrictDecoder().Decode(rawYAML, nil, nil); err != nil {
		return fmt.Errorf("strict decode: %w", err)
	}

	if schemaValidation {
		if errs := validation.ValidateCustomResource(nil, &us, validator); len(errs) > 0 {
			return errs.ToAggregate()
		}
	}

	return nil
}
