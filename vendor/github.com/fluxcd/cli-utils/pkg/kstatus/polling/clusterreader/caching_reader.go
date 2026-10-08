// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterreader

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/object"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/pager"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This map is hard-coded knowledge that a Deployment contains and
// ReplicaSet, and that a ReplicaSet in turn contains Pods, etc., and the
// approach to finding status being used here requires hardcoding that
// knowledge in the status client library.
// TODO: These should probably be defined in the statusreaders rather than here.
var genGroupKinds = map[schema.GroupKind][]schema.GroupKind{
	schema.GroupKind{Group: "apps", Kind: "Deployment"}: { //nolint:gofmt
		{
			Group: "apps",
			Kind:  "ReplicaSet",
		},
	},
	schema.GroupKind{Group: "apps", Kind: "ReplicaSet"}: { //nolint:gofmt
		{
			Group: "",
			Kind:  "Pod",
		},
	},
	schema.GroupKind{Group: "apps", Kind: "StatefulSet"}: { //nolint:gofmt
		{
			Group: "",
			Kind:  "Pod",
		},
	},
}

// NewCachingClusterReader returns a new instance of the ClusterReader. The
// ClusterReader needs will use the clusterreader to fetch resources from the cluster,
// while the mapper is used to resolve the version for GroupKinds. The set of
// identifiers is needed so the ClusterReader can figure out which GroupKind
// and namespace combinations it needs to cache when the Sync function is called.
// We only want to fetch the resources that are actually needed.
func NewCachingClusterReader(reader client.Reader, mapper meta.RESTMapper, identifiers object.ObjMetadataSet) (engine.ClusterReader, error) {
	gvkNamespaceSet := newGnSet()
	for _, id := range identifiers {
		// For every identifier, add the GroupVersionKind and namespace combination to the gvkNamespaceSet and
		// check the genGroupKinds map for any generated resources that also should be included.
		err := buildGvkNamespaceSet([]schema.GroupKind{id.GroupKind}, id.Namespace, gvkNamespaceSet)
		if err != nil {
			return nil, err
		}
	}

	return &CachingClusterReader{
		reader: reader,
		mapper: mapper,
		gns:    gvkNamespaceSet.gvkNamespaces,
	}, nil
}

func buildGvkNamespaceSet(gks []schema.GroupKind, namespace string, gvkNamespaceSet *gvkNamespaceSet) error {
	for _, gk := range gks {
		gvkNamespaceSet.add(gkNamespace{
			GroupKind: gk,
			Namespace: namespace,
		})
		genGKs, found := genGroupKinds[gk]
		if found {
			err := buildGvkNamespaceSet(genGKs, namespace, gvkNamespaceSet)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type gvkNamespaceSet struct {
	gvkNamespaces []gkNamespace
	seen          map[gkNamespace]struct{}
}

func newGnSet() *gvkNamespaceSet {
	return &gvkNamespaceSet{
		seen: make(map[gkNamespace]struct{}),
	}
}

func (g *gvkNamespaceSet) add(gn gkNamespace) {
	if _, found := g.seen[gn]; !found {
		g.gvkNamespaces = append(g.gvkNamespaces, gn)
		g.seen[gn] = struct{}{}
	}
}

// CachingClusterReader is an implementation of the ObserverReader interface that will
// pre-fetch all resources needed before every sync loop. The resources needed are decided by
// finding all combinations of GroupVersionKind and namespace referenced by the provided
// identifiers. This list is then expanded to include any known generated resource types.
type CachingClusterReader struct {
	mx sync.RWMutex

	// clusterreader provides functions to read and list resources from the
	// cluster.
	reader client.Reader

	// mapper is the client-side representation of the server-side scheme. It is used
	// to resolve GroupVersionKind from GroupKind.
	mapper meta.RESTMapper

	// gns contains the slice of all the GVK and namespace combinations that
	// should be included in the cache. This is computed based the resource identifiers
	// passed in when the CachingClusterReader is created and augmented with other
	// resource types needed to compute status (see genGroupKinds).
	gns []gkNamespace

	// cache contains the resources found in the cluster for the given combination
	// of GVK and namespace. Before each polling cycle, the framework will call the
	// Sync function, which is responsible for repopulating the cache.
	cache map[gkNamespace]cacheEntry
}

type cacheEntry struct {
	resources unstructured.UnstructuredList
	err       error
}

// gkNamespace contains information about a GroupVersionKind and a namespace.
type gkNamespace struct {
	GroupKind schema.GroupKind
	Namespace string
}

// Get looks up the resource identified by the key and the object GVK in the cache. If the needed combination
// of GVK and namespace is not part of the cache, that is considered an error.
func (c *CachingClusterReader) Get(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
	c.mx.RLock()
	defer c.mx.RUnlock()
	gvk := obj.GetObjectKind().GroupVersionKind()
	mapping, err := c.mapper.RESTMapping(gvk.GroupKind())
	if err != nil {
		return err
	}
	gn := gkNamespace{
		GroupKind: gvk.GroupKind(),
		Namespace: key.Namespace,
	}
	cacheEntry, found := c.cache[gn]
	if !found {
		return fmt.Errorf("GVK %s and Namespace %s not found in cache", gvk.String(), gn.Namespace)
	}

	if cacheEntry.err != nil {
		return cacheEntry.err
	}
	for _, u := range cacheEntry.resources.Items {
		if u.GetName() == key.Name {
			obj.Object = u.Object
			return nil
		}
	}
	return apierrors.NewNotFound(mapping.Resource.GroupResource(), key.Name)
}

// ListNamespaceScoped lists all resource identifier by the GVK of the list, the namespace and the selector
// from the cache. If the needed combination of GVK and namespace is not part of the cache, that is considered an error.
func (c *CachingClusterReader) ListNamespaceScoped(_ context.Context, list *unstructured.UnstructuredList, namespace string, selector labels.Selector) error {
	c.mx.RLock()
	defer c.mx.RUnlock()
	gvk := list.GroupVersionKind()
	gn := gkNamespace{
		GroupKind: gvk.GroupKind(),
		Namespace: namespace,
	}

	cacheEntry, found := c.cache[gn]
	if !found {
		return fmt.Errorf("GVK %s and Namespace %s not found in cache", gvk.String(), gn.Namespace)
	}

	if cacheEntry.err != nil {
		return cacheEntry.err
	}

	var items []unstructured.Unstructured
	for _, u := range cacheEntry.resources.Items {
		if selector.Matches(labels.Set(u.GetLabels())) {
			items = append(items, u)
		}
	}
	list.Items = items
	return nil
}

// ListClusterScoped lists all resource identifier by the GVK of the list and selector
// from the cache. If the needed combination of GVK and namespace (which for clusterscoped resources
// will always be the empty string) is not part of the cache, that is considered an error.
func (c *CachingClusterReader) ListClusterScoped(ctx context.Context, list *unstructured.UnstructuredList, selector labels.Selector) error {
	return c.ListNamespaceScoped(ctx, list, "", selector)
}

// Sync loops over the list of gkNamespace we know of, and uses list calls to fetch the resources.
// This information populates the cache.
func (c *CachingClusterReader) Sync(ctx context.Context) error {
	c.mx.Lock()
	defer c.mx.Unlock()
	cache := make(map[gkNamespace]cacheEntry)
	for _, gn := range c.gns {
		mapping, err := c.mapper.RESTMapping(gn.GroupKind)
		if err != nil {
			if meta.IsNoMatchError(err) {
				// If we get a NoMatchError, it means we are checking for
				// a type that doesn't exist. Presumably the CRD is being
				// applied, so it will be added. Reset the RESTMapper to
				// make sure we pick up any new resource types on the
				// APIServer.
				cache[gn] = cacheEntry{
					err: err,
				}
				continue
			}
			return err
		}
		ns := ""
		if mapping.Scope == meta.RESTScopeNamespace {
			ns = gn.Namespace
		}
		list, err := c.listUnstructured(ctx, mapping.GroupVersionKind, ns)
		if err != nil {
			// If the context was cancelled, we just stop the work and return
			// the error.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// For other errors, we just keep it the error. Whenever any pollers
			// request a resource covered by this gns, we just return the
			// error.
			cache[gn] = cacheEntry{
				err: err,
			}
			continue
		}
		cache[gn] = cacheEntry{
			resources: *list,
		}
	}
	c.cache = cache
	return nil
}

// listUnstructured performs one or more LIST calls, paginating the requests
// and aggregating the results.  If aggregated, only the ResourceVersion,
// SelfLink, and Items will be populated. The default page size is 500.
func (c *CachingClusterReader) listUnstructured(
	ctx context.Context,
	gvk schema.GroupVersionKind,
	namespace string,
) (*unstructured.UnstructuredList, error) {
	mOpts := metav1.ListOptions{}
	mOpts.SetGroupVersionKind(gvk)
	obj, _, err := pager.New(c.listPageFunc(namespace)).List(ctx, mOpts)
	if err != nil {
		return nil, err
	}

	switch t := obj.(type) {
	case *unstructured.UnstructuredList:
		// all in one
		return t, nil
	case *metainternalversion.List:
		// aggregated result
		u := &unstructured.UnstructuredList{}
		u.SetGroupVersionKind(gvk)
		// Only ResourceVersion & SelfLink are copied into the aggregated result
		// by ListPager.
		if t.ResourceVersion != "" {
			u.SetResourceVersion(t.ResourceVersion)
		}
		if t.SelfLink != "" { // nolint:staticcheck
			u.SetSelfLink(t.SelfLink) // nolint:staticcheck
		}
		u.Items = make([]unstructured.Unstructured, len(t.Items))
		for i, item := range t.Items {
			ui, ok := item.(*unstructured.Unstructured)
			if !ok {
				return nil, fmt.Errorf("unexpected list item type: %t", item)
			}
			u.Items[i] = *ui
		}
		return u, nil
	default:
		return nil, fmt.Errorf("unexpected list type: %t", t)
	}
}

func (c *CachingClusterReader) listPageFunc(namespace string) pager.ListPageFunc {
	return func(ctx context.Context, mOpts metav1.ListOptions) (runtime.Object, error) {
		mOptsCopy := mOpts
		labelSelector, err := labels.Parse(mOpts.LabelSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to parse label selector: %w", err)
		}
		fieldSelector, err := fields.ParseSelector(mOpts.FieldSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to parse field selector: %w", err)
		}
		cOpts := &client.ListOptions{
			LabelSelector: labelSelector,
			FieldSelector: fieldSelector,
			Namespace:     namespace,
			Limit:         mOpts.Limit,
			Continue:      mOpts.Continue,
			Raw:           &mOptsCopy,
		}
		var list unstructured.UnstructuredList
		list.SetGroupVersionKind(mOpts.GroupVersionKind())
		// Note: client.ListOptions only supports Exact ResourceVersion matching.
		// So leave ResourceVersion blank to get Any ResourceVersion.
		err = c.reader.List(ctx, &list, cOpts)
		return &list, err
	}
}
