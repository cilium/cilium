// Copyright 2016-2018 Authors of Cilium
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

package endpoint

import (
	"errors"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"k8s.io/client-go/rest"

	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
)

// getCiliumClient builds and returns a k8s auto-generated client for cilium
// objects
func getCiliumClient() (ciliumClient cilium_client_v2.CiliumV2Interface, err error) {
	// This allows us to reuse the k8s client
	ciliumEndpointSyncControllerOnce.Do(func() {
		var (
			restConfig *rest.Config
			k8sClient  *clientset.Clientset
		)

		restConfig, err = k8s.CreateConfig()
		if err != nil {
			return
		}

		k8sClient, err = clientset.NewForConfig(restConfig)
		if err != nil {
			return
		}

		ciliumEndpointSyncControllerK8sClient = k8sClient
	})

	if err != nil {
		return nil, err
	}

	// This guards against the situation where another invocation of this
	// function (in another thread or previous in time) might have returned an
	// error and not initialized ciliumEndpointSyncControllerK8sClient
	if ciliumEndpointSyncControllerK8sClient == nil {
		return nil, errors.New("No initialised k8s Cilium CRD client")
	}

	return ciliumEndpointSyncControllerK8sClient.CiliumV2(), nil
}
