/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package envfuncs

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

type namespaceContextKey string

// CreateNamespace provides an Environment.Func that
// creates a new namespace API object and stores it the context
// using its name as key.
//
// NOTE: the returned environment function automatically updates
// the env config, it receives, with the namespace to make it available
// for subsequent call.
func CreateNamespace(name string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, fmt.Errorf("create namespace func: %w", err)
		}
		if err := client.Resources().Create(ctx, &namespace); err != nil {
			return ctx, fmt.Errorf("create namespace func: %w", err)
		}
		cfg.WithNamespace(name) // set env config default namespace
		return context.WithValue(ctx, namespaceContextKey(name), namespace), nil
	}
}

// DeleteNamespace provides an Environment.Func that deletes the named
// namespace. It first searches for the ns in its context, if not found then
// attempt to retrieve it from the API server. Then deletes it.
func DeleteNamespace(name string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var namespace *corev1.Namespace

		// attempt to retrieve from context
		nsVal := ctx.Value(namespaceContextKey(name))
		if nsVal != nil {
			if ns, ok := nsVal.(*corev1.Namespace); ok {
				namespace = ns
			}
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, fmt.Errorf("delete namespace func: %w", err)
		}

		// if not in context, get from server
		if namespace == nil {
			var ns corev1.Namespace
			if err := client.Resources().Get(ctx, name, name, &ns); err != nil {
				return ctx, fmt.Errorf("delete namespace func: %w", err)
			}
			namespace = &ns
		}

		// if still nil, exit
		if namespace == nil {
			return ctx, fmt.Errorf("delete namespace func: namespace not found")
		}

		// remove namespace api object
		if err := client.Resources().Delete(ctx, namespace); err != nil {
			return ctx, fmt.Errorf("delete namespace func: %w", err)
		}

		return ctx, nil
	}
}
