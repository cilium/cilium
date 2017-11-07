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
	"fmt"
	"time"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// CustomResourceDefinitionSingularName is the singular name of custom resource definition
	CustomResourceDefinitionSingularName = "ciliumnetworkpolicy"

	// CustomResourceDefinitionPluralName is the plural name of custom resource definition
	CustomResourceDefinitionPluralName = "ciliumnetworkpolicies"

	// CustomResourceDefinitionKind is the Kind name of custom resource definition
	CustomResourceDefinitionKind = "CiliumNetworkPolicy"

	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.GroupName

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme
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
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// CreateCustomResourceDefinitions creates the CRD object in the kubernetes
// cluster
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	cnpCRDName := CustomResourceDefinitionPluralName + "." + SchemeGroupVersion.Group

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpCRDName,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   SchemeGroupVersion.Group,
			Version: SchemeGroupVersion.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     CustomResourceDefinitionPluralName,
				Singular:   CustomResourceDefinitionSingularName,
				ShortNames: []string{"cnp", "ciliumnp"},
				Kind:       CustomResourceDefinitionKind,
			},
			Scope: apiextensionsv1beta1.NamespaceScoped,
		},
	}

	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	log.Info("Creating v2.CiliumNetworkPolicy CustomResourceDefinition")
	// wait for CRD being established
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		crd, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(cnpCRDName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, err
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					log.Errorf("Name conflict: %s", cond.Reason)
					return false, err
				}
			}
		}
		return false, err
	})
	if err != nil {
		deleteErr := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(cnpCRDName, nil)
		if deleteErr != nil {
			return fmt.Errorf("unable to delete k8s CRD %s. Deleting CRD due: %s", deleteErr, err)
		}
		return err
	}

	return nil
}
