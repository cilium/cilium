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

package v1

import (
	"fmt"
	"time"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"

	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	// ThirdPartyResourcesSingularName is the singular name of third party resources
	ThirdPartyResourcesSingularName = "cilium-network-policy"

	// ThirdPartyResourceGroup is the name of the third party resource group
	ThirdPartyResourceGroup = k8sconst.GroupName

	// CustomResourceDefinitionVersion is the current version of the resource
	ThirdPartyResourceVersion = "v1"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   ThirdPartyResourceGroup,
	Version: ThirdPartyResourceVersion,
}

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
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// CreateThirdPartyResourcesDefinitions creates the TPR object in the kubernetes
// cluster
func CreateThirdPartyResourcesDefinitions(cli kubernetes.Interface) error {
	cnpTPRName := ThirdPartyResourcesSingularName + "." + ThirdPartyResourceGroup
	res := &v1beta1.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpTPRName,
		},
		Description: "Cilium network policy rule",
		Versions: []v1beta1.APIVersion{
			{Name: ThirdPartyResourceVersion},
		},
	}

	_, err := cli.ExtensionsV1beta1().ThirdPartyResources().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	log.Info("Creating v1.CiliumNetworkPolicy ThirdPartyResource")
	// wait for TPR being established
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, err := cli.ExtensionsV1beta1().ThirdPartyResources().Get(cnpTPRName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		// The only way we can know if the TPR was installed in the cluster
		// is to check if the return error was or not nil
		return true, nil
	})
	if err != nil {
		deleteErr := cli.ExtensionsV1beta1().ThirdPartyResources().Delete(cnpTPRName, nil)
		if deleteErr != nil {
			return fmt.Errorf("unable to delete k8s TPR %s. Deleting TPR due: %s", deleteErr, err)
		}
		return err
	}

	return nil
}
