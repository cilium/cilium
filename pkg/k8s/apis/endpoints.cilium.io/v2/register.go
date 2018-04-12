// Copyright 2017 Authors of Cilium
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

package v2

import (
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/endpoints.cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/utils"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sConst.GroupName

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v1"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	CustomResourceDefinitionSchemaVersion = "1.7"
)

var (
	// SchemeGroupVersion is group version used to register these objects
	SchemeGroupVersion = schema.GroupVersion{
		Group:   CustomResourceDefinitionGroup,
		Version: CustomResourceDefinitionVersion,
	}

	// cepCRV is a minimal validation for CEP objects. Since only the agent is
	// creating them, it is better to be permissive and have some data, if buggy,
	// than to have no data in k8s.
	cepCRV = apiextensionsv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{},
	}
)

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kuberentes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CiliumEndpoint{},
		&CiliumEndpointList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// CreateCustomResourceDefinitions creates and updates the CiliumEndpoint CRD.
// It should be called on agent startup but is idempotent and safe to call
// again.
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {

	// remove the cilium.io CEP CRD so it doesn't hold on to the shortnames
	if err := k8sUtils.DeleteCRD(clientset, "ciliumendpoints.cilium.io"); err != nil {
		log.WithError(err).Error("Cannot clean obsolete ciliumendpoint k8s CRD")
	}

	var (
		// CustomResourceDefinitionSingularName is the singular name of custom resource definition
		CustomResourceDefinitionSingularName = "ciliumendpoint"

		// CustomResourceDefinitionPluralName is the plural name of custom resource definition
		CustomResourceDefinitionPluralName = "ciliumendpoints"

		// CustomResourceDefinitionShortNames are the abbreviated names to refer to this CRD's instances
		CustomResourceDefinitionShortNames = []string{"cep", "ciliumep"}

		// CustomResourceDefinitionKind is the Kind name of custom resource definition
		CustomResourceDefinitionKind = "CiliumEndpoint"

		CRDName = CustomResourceDefinitionPluralName + "." + SchemeGroupVersion.Group
	)

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: CRDName,
			Labels: map[string]string{
				k8sUtils.CustomResourceDefinitionSchemaVersionKey: CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   SchemeGroupVersion.Group,
			Version: SchemeGroupVersion.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     CustomResourceDefinitionPluralName,
				Singular:   CustomResourceDefinitionSingularName,
				ShortNames: CustomResourceDefinitionShortNames,
				Kind:       CustomResourceDefinitionKind,
			},
			Scope:      apiextensionsv1beta1.NamespaceScoped,
			Validation: &cepCRV,
		},
	}

	return k8sUtils.CreateUpdateCRD(clientset, "CiliumEndpoint/"+SchemeGroupVersion.Version, res)
}
