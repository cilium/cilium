// Copyright 2016-2020 Authors of Cilium
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

package k8s

import (
	"context"
	"fmt"

	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"

	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// K8sClient is a wrapper around kubernetes.Interface.
type K8sClient struct {
	// kubernetes.Interface is the object through which interactions with
	// Kubernetes are performed.
	kubernetes.Interface
}

// K8sCiliumClient is a wrapper around clientset.Interface.
type K8sCiliumClient struct {
	clientset.Interface
}

// GetSecrets returns the secrets found in the given namespace and name.
func (k8sCli K8sClient) GetSecrets(ctx context.Context, ns, name string) (map[string][]byte, error) {
	if k8sCli.Interface == nil {
		return nil, fmt.Errorf("GetSecrets: No k8s, cannot access k8s secrets")
	}

	result := &coreV1.Secret{}
	err := k8sCli.CoreV1().RESTClient().Get().
		Context(ctx).
		Namespace(ns).
		Resource("secrets").
		Name(name).
		VersionedParams(&v1.GetOptions{}, scheme.ParameterCodec).
		Do().
		Into(result)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}
