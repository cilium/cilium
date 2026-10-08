// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterreader

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewDirectClusterReader creates a new implementation of the engine.ClusterReader interface that makes
// calls directly to the cluster without any caching.
func NewDirectClusterReader(reader client.Reader, _ meta.RESTMapper, _ object.ObjMetadataSet) (engine.ClusterReader, error) {
	return &DirectClusterReader{
		Reader: reader,
	}, nil
}

// DirectClusterReader is an implementation of the ClusterReader that just delegates all calls directly to
// the underlying clusterreader. No caching.
type DirectClusterReader struct {
	Reader client.Reader
}

func (n *DirectClusterReader) Get(ctx context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
	return n.Reader.Get(ctx, key, obj)
}

func (n *DirectClusterReader) ListNamespaceScoped(ctx context.Context, list *unstructured.UnstructuredList, namespace string, selector labels.Selector) error {
	return n.Reader.List(ctx, list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector})
}

func (n *DirectClusterReader) ListClusterScoped(ctx context.Context, list *unstructured.UnstructuredList, selector labels.Selector) error {
	return n.Reader.List(ctx, list, client.MatchingLabelsSelector{Selector: selector})
}

func (n *DirectClusterReader) Sync(_ context.Context) error {
	return nil
}
