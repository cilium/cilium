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

package main

import (
	"context"
	"errors"
	"fmt"

	operatorOption "github.com/cilium/cilium/operator/option"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	toolswatch "k8s.io/client-go/tools/watch"
)

// waitForCRD waits for the given CRD to be available with the given context.
func waitForCRD(ctx context.Context, client clientset.Interface, name string) error {
	log.Infof("Waiting for CRD %s to be available", name)
	selector := fields.OneTermEqualSelector("metadata.name", name).String()
	w := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector

			if k8sversion.Capabilities().APIExtensionsV1CRD {
				return client.ApiextensionsV1().CustomResourceDefinitions().List(ctx, options)
			}

			return client.ApiextensionsV1beta1().CustomResourceDefinitions().List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector

			if k8sversion.Capabilities().APIExtensionsV1CRD {
				return client.ApiextensionsV1().CustomResourceDefinitions().Watch(ctx, options)
			}

			return client.ApiextensionsV1beta1().CustomResourceDefinitions().Watch(ctx, options)
		},
	}

	cond := func(ev watch.Event) (bool, error) {
		var (
			crdName string
			ok      bool
		)

		if k8sversion.Capabilities().APIExtensionsV1CRD {
			var crd *v1.CustomResourceDefinition
			if crd, ok = ev.Object.(*v1.CustomResourceDefinition); ok {
				crdName = crd.ObjectMeta.Name
			}
		} else {
			var crd *v1beta1.CustomResourceDefinition
			if crd, ok = ev.Object.(*v1beta1.CustomResourceDefinition); ok {
				crdName = crd.ObjectMeta.Name
			}
		}

		if ok {
			// NOTE(mrostecki): Why is it done here despite having a field
			// selector above? Fake client doesn't support field selectors,
			// so the fake watcher always returns all CRDs created...
			// kubernetes/client-go#326
			// Doing that one comparison doesn't hurt and it makes unit
			// testing possible.
			if crdName == name {
				return true, nil
			}
			return false, errors.New("CRD not found")
		}

		return false, ErrInvalidTypeCRD
	}

	var (
		ev  *watch.Event
		err error
	)
	if k8sversion.Capabilities().APIExtensionsV1CRD {
		ev, err = toolswatch.UntilWithSync(ctx, w, &v1.CustomResourceDefinition{}, nil, cond)
	} else {
		ev, err = toolswatch.UntilWithSync(ctx, w, &v1beta1.CustomResourceDefinition{}, nil, cond)
	}
	if err != nil {
		return fmt.Errorf("timeout waiting for CRD %s: %w", name, err)
	}

	var ok bool
	if k8sversion.Capabilities().APIExtensionsV1CRD {
		_, ok = ev.Object.(*v1.CustomResourceDefinition)
	} else {
		_, ok = ev.Object.(*v1beta1.CustomResourceDefinition)
	}
	if ok {
		log.Infof("CRD %s found", name)
		return nil
	}

	return ErrInvalidTypeCRD
}

// WaitForCRD waits for the given CRD to be available until the default timeout,
// after which cilium-agent should be ready. Returns an error when timeout
// is exceeded.
func WaitForCRD(client clientset.Interface, name string) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), operatorOption.Config.CRDWaitTimeout)
	defer cancelFunc()
	return waitForCRD(ctx, client, name)
}
