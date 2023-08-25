// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"encoding/json"
	"fmt"

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
)

// NPValidator is a validator structure used to validate CNP and CCNP.
type NPValidator struct {
	cnpValidator  validation.SchemaCreateValidator
	ccnpValidator validation.SchemaCreateValidator
}

func NewNPValidator() (*NPValidator, error) {
	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CNPCRV to have those
	// default values, the same way k8s api-server has it.
	cnpCRVJSONBytes, err := json.Marshal(
		client.GetPregeneratedCRD(client.CNPCRDName).Spec.Versions[0].Schema,
	)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CNPCRV: %w", err)
	}
	var cnpCRV apiextensionsv1.CustomResourceValidation
	err = json.Unmarshal(cnpCRVJSONBytes, &cnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CNPCRV: %w", err)
	}

	var cnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&cnpCRV,
		&cnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	cnpValidator, _, err := validation.NewSchemaValidator(cnpInternal.OpenAPIV3Schema)
	if err != nil {
		return nil, err
	}

	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CCNPCRV to have those
	// default values, the same way k8s api-server has it.
	ccnpCRVJSONBytes, err := json.Marshal(
		client.GetPregeneratedCRD(client.CCNPCRDName).Spec.Versions[0].Schema,
	)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CCNPCRV: %w", err)
	}
	var ccnpCRV apiextensionsv1.CustomResourceValidation
	err = json.Unmarshal(ccnpCRVJSONBytes, &ccnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CCNPCRV: %w", err)
	}

	var ccnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&ccnpCRV,
		&ccnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	ccnpValidator, _, err := validation.NewSchemaValidator(ccnpInternal.OpenAPIV3Schema)
	if err != nil {
		return nil, err
	}

	return &NPValidator{
		cnpValidator:  cnpValidator,
		ccnpValidator: ccnpValidator,
	}, nil
}

// ValidateCNP validates the given CNP accordingly the CNP validation schema.
func (n *NPValidator) ValidateCNP(cnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &cnp, n.cnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(cnp); err != nil {
		return err
	}

	return nil
}

// ValidateCCNP validates the given CCNP accordingly the CCNP validation schema.
func (n *NPValidator) ValidateCCNP(ccnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &ccnp, n.ccnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(ccnp); err != nil {
		return err
	}

	return nil
}
