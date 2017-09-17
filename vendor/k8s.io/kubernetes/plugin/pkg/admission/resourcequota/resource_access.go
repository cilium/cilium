/*
Copyright 2016 The Kubernetes Authors.

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

package resourcequota

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/storage/etcd"
	"k8s.io/kubernetes/pkg/api"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	corelisters "k8s.io/kubernetes/pkg/client/listers/core/internalversion"
)

// QuotaAccessor abstracts the get/set logic from the rest of the Evaluator.  This could be a test stub, a straight passthrough,
// or most commonly a series of deconflicting caches.
type QuotaAccessor interface {
	// UpdateQuotaStatus is called to persist final status.  This method should write to persistent storage.
	// An error indicates that write didn't complete successfully.
	UpdateQuotaStatus(newQuota *api.ResourceQuota) error

	// GetQuotas gets all possible quotas for a given namespace
	GetQuotas(namespace string) ([]api.ResourceQuota, error)
}

type quotaAccessor struct {
	client clientset.Interface

	// lister can list/get quota objects from a shared informer's cache
	lister corelisters.ResourceQuotaLister

	// liveLookups holds the last few live lookups we've done to help ammortize cost on repeated lookup failures.
	// This let's us handle the case of latent caches, by looking up actual results for a namespace on cache miss/no results.
	// We track the lookup result here so that for repeated requests, we don't look it up very often.
	liveLookupCache *lru.Cache
	liveTTL         time.Duration
	// updatedQuotas holds a cache of quotas that we've updated.  This is used to pull the "really latest" during back to
	// back quota evaluations that touch the same quota doc.  This only works because we can compare etcd resourceVersions
	// for the same resource as integers.  Before this change: 22 updates with 12 conflicts.  after this change: 15 updates with 0 conflicts
	updatedQuotas *lru.Cache
}

// newQuotaAccessor creates an object that conforms to the QuotaAccessor interface to be used to retrieve quota objects.
func newQuotaAccessor() (*quotaAccessor, error) {
	liveLookupCache, err := lru.New(100)
	if err != nil {
		return nil, err
	}
	updatedCache, err := lru.New(100)
	if err != nil {
		return nil, err
	}

	// client and lister will be set when SetInternalKubeClientSet and SetInternalKubeInformerFactory are invoked
	return &quotaAccessor{
		liveLookupCache: liveLookupCache,
		liveTTL:         time.Duration(30 * time.Second),
		updatedQuotas:   updatedCache,
	}, nil
}

func (e *quotaAccessor) UpdateQuotaStatus(newQuota *api.ResourceQuota) error {
	updatedQuota, err := e.client.Core().ResourceQuotas(newQuota.Namespace).UpdateStatus(newQuota)
	if err != nil {
		return err
	}

	key := newQuota.Namespace + "/" + newQuota.Name
	e.updatedQuotas.Add(key, updatedQuota)
	return nil
}

var etcdVersioner = etcd.APIObjectVersioner{}

// checkCache compares the passed quota against the value in the look-aside cache and returns the newer
// if the cache is out of date, it deletes the stale entry.  This only works because of etcd resourceVersions
// being monotonically increasing integers
func (e *quotaAccessor) checkCache(quota *api.ResourceQuota) *api.ResourceQuota {
	key := quota.Namespace + "/" + quota.Name
	uncastCachedQuota, ok := e.updatedQuotas.Get(key)
	if !ok {
		return quota
	}
	cachedQuota := uncastCachedQuota.(*api.ResourceQuota)

	if etcdVersioner.CompareResourceVersion(quota, cachedQuota) >= 0 {
		e.updatedQuotas.Remove(key)
		return quota
	}
	return cachedQuota
}

func (e *quotaAccessor) GetQuotas(namespace string) ([]api.ResourceQuota, error) {
	// determine if there are any quotas in this namespace
	// if there are no quotas, we don't need to do anything
	items, err := e.lister.ResourceQuotas(namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("error resolving quota: %v", err)
	}

	// if there are no items held in our indexer, check our live-lookup LRU, if that misses, do the live lookup to prime it.
	if len(items) == 0 {
		lruItemObj, ok := e.liveLookupCache.Get(namespace)
		if !ok || lruItemObj.(liveLookupEntry).expiry.Before(time.Now()) {
			// TODO: If there are multiple operations at the same time and cache has just expired,
			// this may cause multiple List operations being issued at the same time.
			// If there is already in-flight List() for a given namespace, we should wait until
			// it is finished and cache is updated instead of doing the same, also to avoid
			// throttling - see #22422 for details.
			liveList, err := e.client.Core().ResourceQuotas(namespace).List(metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			newEntry := liveLookupEntry{expiry: time.Now().Add(e.liveTTL)}
			for i := range liveList.Items {
				newEntry.items = append(newEntry.items, &liveList.Items[i])
			}
			e.liveLookupCache.Add(namespace, newEntry)
			lruItemObj = newEntry
		}
		lruEntry := lruItemObj.(liveLookupEntry)
		for i := range lruEntry.items {
			items = append(items, lruEntry.items[i])
		}
	}

	resourceQuotas := []api.ResourceQuota{}
	for i := range items {
		quota := items[i]
		quota = e.checkCache(quota)
		// always make a copy.  We're going to muck around with this and we should never mutate the originals
		resourceQuotas = append(resourceQuotas, *quota)
	}

	return resourceQuotas, nil
}
