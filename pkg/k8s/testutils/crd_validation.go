// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sYaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
)

var (
	crdSchemaValidatorsOnce sync.Once
	crdSchemaValidators     map[schema.GroupVersionKind]validation.SchemaCreateValidator

	strictDecoderOnce sync.Once
	strictDecoder     runtime.Decoder
)

func getCRDSchemaValidators(logger *slog.Logger) map[schema.GroupVersionKind]validation.SchemaCreateValidator {
	crdSchemaValidatorsOnce.Do(func() {
		crdSchemaValidators = make(map[schema.GroupVersionKind]validation.SchemaCreateValidator)
		for _, crdList := range client.CustomResourceDefinitionList() {
			crd := client.GetPregeneratedCRD(logger, crdList.Name)
			for _, version := range crd.Spec.Versions {
				if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
					continue
				}
				v, err := schemaValidatorFor(version.Schema)
				if err != nil {
					// A bad embedded schema is a build-time bug, not test input;
					// skip it rather than poisoning the whole map.
					logger.Warn("skipping CRD schema validator",
						"crd", crdList.Name, "version", version.Name, "error", err)
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
	})
	return crdSchemaValidators
}

func schemaValidatorFor(crv *apiextensionsv1.CustomResourceValidation) (validation.SchemaCreateValidator, error) {
	// Round-trip through JSON to apply the schema's defaults, as the apiserver does.
	crvJSON, err := json.Marshal(crv)
	if err != nil {
		return nil, fmt.Errorf("marshalling CRD validation: %w", err)
	}
	var crvV1 apiextensionsv1.CustomResourceValidation
	if err := json.Unmarshal(crvJSON, &crvV1); err != nil {
		return nil, fmt.Errorf("unmarshalling CRD validation: %w", err)
	}

	var crvInternal apiextensionsinternal.CustomResourceValidation
	if err := apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&crvV1, &crvInternal, nil,
	); err != nil {
		return nil, err
	}

	v, _, err := validation.NewSchemaValidator(crvInternal.OpenAPIV3Schema)
	return v, err
}

func getStrictDecoder() runtime.Decoder {
	strictDecoderOnce.Do(func() {
		strictDecoder = serializer.NewCodecFactory(Scheme, serializer.EnableStrict).UniversalDeserializer()
	})
	return strictDecoder
}

// ValidateCRD validates a raw CRD YAML document against the embedded CRD
// schemas, as the kube-apiserver would: OpenAPI schema validation plus a strict
// decode to reject unknown fields.
//
// supported reports whether the document's kind is a Cilium CRD with a known
// schema; callers feeding arbitrary objects should skip validation when it is
// false rather than treating it as an error. Malformed input returns an error
// with supported=false.
//
// Callers must pass raw YAML, not a decoded object: a typed decode silently
// drops unknown fields, defeating the typo detection.
func ValidateCRD(logger *slog.Logger, rawYAML []byte) (supported bool, err error) {
	jsonBytes, err := k8sYaml.YAMLToJSON(rawYAML)
	if err != nil {
		return false, fmt.Errorf("converting YAML to JSON: %w", err)
	}

	var us unstructured.Unstructured
	if err := json.Unmarshal(jsonBytes, &us); err != nil {
		return false, fmt.Errorf("decoding into unstructured: %w", err)
	}

	validator, ok := getCRDSchemaValidators(logger)[us.GroupVersionKind()]
	if !ok {
		return false, nil
	}

	if errs := validation.ValidateCustomResource(nil, &us, validator); len(errs) > 0 {
		return true, errs.ToAggregate()
	}

	// Stricter than the apiserver, which prunes unknown fields rather than
	// rejecting them; surfaces typos that would otherwise be silently dropped.
	if _, _, err := getStrictDecoder().Decode(jsonBytes, nil, nil); err != nil {
		return true, fmt.Errorf("strict decode: %w", err)
	}

	return true, nil
}
