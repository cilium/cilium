// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterreader

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DynamicClusterReader is an implementation of the ClusterReader that delegates
// all calls directly to the underlying DynamicClient. No caching.
type DynamicClusterReader struct {
	DynamicClient dynamic.Interface
	Mapper        meta.RESTMapper
}

func (n *DynamicClusterReader) Get(ctx context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
	mapping, err := n.Mapper.RESTMapping(obj.GroupVersionKind().GroupKind())
	if err != nil {
		return fmt.Errorf("failed to map object: %w", err)
	}

	serverObj, err := n.DynamicClient.Resource(mapping.Resource).
		Namespace(key.Namespace).
		Get(ctx, key.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	serverObj.DeepCopyInto(obj)
	return nil
}

func (n *DynamicClusterReader) ListNamespaceScoped(ctx context.Context, list *unstructured.UnstructuredList, namespace string, selector labels.Selector) error {
	mapping, err := n.Mapper.RESTMapping(list.GroupVersionKind().GroupKind())
	if err != nil {
		return fmt.Errorf("failed to map object: %w", err)
	}

	serverObj, err := n.DynamicClient.Resource(mapping.Resource).
		Namespace(namespace).
		List(ctx, metav1.ListOptions{
			LabelSelector: selector.String(),
		})
	if err != nil {
		return err
	}

	serverObj.DeepCopyInto(list)
	return nil
}

func (n *DynamicClusterReader) ListClusterScoped(ctx context.Context, list *unstructured.UnstructuredList, selector labels.Selector) error {
	mapping, err := n.Mapper.RESTMapping(list.GroupVersionKind().GroupKind())
	if err != nil {
		return fmt.Errorf("failed to map object: %w", err)
	}

	serverObj, err := n.DynamicClient.Resource(mapping.Resource).
		List(ctx, metav1.ListOptions{
			LabelSelector: selector.String(),
		})
	if err != nil {
		return err
	}

	serverObj.DeepCopyInto(list)
	return nil
}

func (n *DynamicClusterReader) Sync(_ context.Context) error {
	return nil
}
