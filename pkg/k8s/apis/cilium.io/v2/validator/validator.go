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

package validator

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/client"

	"github.com/go-openapi/validate"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NPValidator is a validator structure used to validate CNP.
type NPValidator struct {
	cnpValidator  *validate.SchemaValidator
	ccnpValidator *validate.SchemaValidator
}

func NewNPValidator() (*NPValidator, error) {
	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CNPCRV to have those
	// default values, the same way k8s api-server has it.
	cnpCRVJSONBytes, err := json.Marshal(client.CNPCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CNPCRV: %w", err)
	}
	var cnpCRV apiextensionsv1beta1.CustomResourceValidation
	err = json.Unmarshal(cnpCRVJSONBytes, &cnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CNPCRV: %w", err)
	}

	var cnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1beta1.Convert_v1beta1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&cnpCRV,
		&cnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	cnpValidator, _, err := validation.NewSchemaValidator(&cnpInternal)
	if err != nil {
		return nil, err
	}

	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CNPCRV to have those
	// default values, the same way k8s api-server has it.
	ccnpCRVJSONBytes, err := json.Marshal(client.CCNPCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CCNPCRV: %w", err)
	}
	var ccnpCRV apiextensionsv1beta1.CustomResourceValidation
	err = json.Unmarshal(ccnpCRVJSONBytes, &ccnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CCNPCRV: %w", err)
	}

	var ccnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1beta1.Convert_v1beta1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&ccnpCRV,
		&ccnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	ccnpValidator, _, err := validation.NewSchemaValidator(&ccnpInternal)
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
	return nil
}

// ValidateCCNP validates the given CCNP accordingly the CCNP validation schema.
func (n *NPValidator) ValidateCCNP(ccnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &ccnp, n.ccnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}
	return nil
}
