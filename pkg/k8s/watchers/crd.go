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

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) crdsInit(ctx context.Context, client apiextclientset.Interface) error {
	crds := newCRDState(
		map[string]bool{
			cnpCRD:  false,
			ccnpCRD: false,
			cepCRD:  false,
			cnCRD:   false,
			cidCRD:  false,
			clrpCRD: false,
		},
	)

	var (
		listerWatcher = newListWatchFromClient(
			newCRDGetter(client),
			fields.Everything(),
			k8sversion.Capabilities().WatchPartialObjectMetadata,
		)

		crdController cache.Controller
	)
	if k8sversion.Capabilities().WatchPartialObjectMetadata {
		_, crdController = informer.NewInformer(
			listerWatcher,
			&metav1.PartialObjectMetadata{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { addCRD(&crds, obj) },
				DeleteFunc: func(obj interface{}) { deleteCRD(&crds, obj) },
			},
			nil,
		)
	} else {
		// Note that we are watching for v1beta1 version of the CRD because
		// support for v1 CRDs was introduced in K8s 1.16. Because support for
		// watching metav1.POM was only introduced in 1.15, we can safely
		// assume this apiserver only has v1beta1 CRDs.
		_, crdController = informer.NewInformer(
			listerWatcher,
			&v1beta1.CustomResourceDefinition{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { addCRD(&crds, obj) },
				DeleteFunc: func(obj interface{}) { deleteCRD(&crds, obj) },
			},
			nil,
		)
	}

	// Create a context so that we can timeout after the configured CRD wait
	// peroid.
	ctx, cancel := context.WithTimeout(ctx, option.Config.CRDWaitTimeout)
	defer cancel()

	crds.Lock()
	for crd := range crds.m {
		k.blockWaitGroupToSyncResources(
			ctx.Done(),
			nil,
			func() bool {
				crds.Lock()
				defer crds.Unlock()
				return crds.m[crd]
			},
			crd,
		)
	}
	crds.Unlock()

	// The above loop will call blockWaitGroupToSyncResources to populate the
	// K8sWatcher state with the current state of the CRDs. It will check the
	// state of each CRD, with the inline function provided. If the function
	// reports that the given CRD is true (has been synced), it will close a
	// channel associated with the given CRD. A subsequent call to
	// (*K8sWatcher).WaitForCacheSync will notice that a given CRD's channel
	// has been closed. Once all the CRDs passed to WaitForCacheSync have had
	// their channels closed, the function unblocks.
	//
	// Meanwhile, the below code kicks off the controller that was instantiated
	// above, and enters a loop looking for (1) if the context has deadlined or
	// (2) if the entire CRD state has been synced (all CRDs found in the
	// cluster). While we're in for-select loop, the controller is listening
	// for either add or delete events to the customresourcedefinition resource
	// (disguised inside a metav1.PartialObjectMetadata object). If (1) is
	// encountered, then Cilium will fatal because it cannot proceed if the
	// CRDs are not present. If (2) is encountered, then make sure the
	// controller has exited by cancelling the context and we return out.

	go crdController.Run(ctx.Done())
	k.k8sAPIGroups.addAPI(k8sAPIGroupCRD)
	// We no longer need this API to show up in `cilum status` as the
	// controller will exit after this function.
	defer k.k8sAPIGroups.removeAPI(k8sAPIGroupCRD)

	log.Info("Waiting until all Cilium CRDs are available")

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err != nil && !errors.Is(err, context.Canceled) {
				log.WithError(err).
					Fatalf("Unable to find all Cilium CRDs necessary within "+
						"%v timeout. Please ensure that Cilium Operator is "+
						"running, as it's responsible for registering all "+
						"the Cilium CRDs. The following CRDs were not found: %v",
						option.Config.CRDWaitTimeout, crds.unSynced())
			}
			// If the context was canceled it means the daemon is being stopped
			// so we can return the context's error.
			return err
		case <-ticker.C:
			if crds.isSynced() {
				ticker.Stop()
				log.Info("All Cilium CRDs have been found and are available")
				return nil
			}
		}
	}
}

func addCRD(crds *crdState, obj interface{}) {
	if k8sversion.Capabilities().WatchPartialObjectMetadata {
		if pom := k8s.ObjToV1PartialObjectMetadata(obj); pom != nil {
			crds.Lock()
			crds.m[crdResourceName(pom.GetName())] = true
			crds.Unlock()
		}
	} else {
		if crd := k8s.ObjToV1beta1CRD(obj); crd != nil {
			crds.Lock()
			crds.m[crdResourceName(crd.GetName())] = true
			crds.Unlock()
		}
	}
}

func deleteCRD(crds *crdState, obj interface{}) {
	if k8sversion.Capabilities().WatchPartialObjectMetadata {
		if pom := k8s.ObjToV1PartialObjectMetadata(obj); pom != nil {
			crds.Lock()
			crds.m[crdResourceName(pom.GetName())] = false
			crds.Unlock()
		}
	} else {
		if crd := k8s.ObjToV1beta1CRD(obj); crd != nil {
			crds.Lock()
			crds.m[crdResourceName(crd.GetName())] = false
			crds.Unlock()
		}
	}
}

// isSynced returns whether all the CRDs inside `m` have all been synced,
// meaning all CRDs we care about in Cilium exist in the cluster.
func (s *crdState) isSynced() bool {
	s.Lock()
	defer s.Unlock()
	for _, synced := range s.m {
		if !synced {
			return false
		}
	}
	return true
}

// unSynced returns a slice containing all CRDs that currently have not been
// synced.
func (s *crdState) unSynced() []string {
	s.Lock()
	defer s.Unlock()
	u := make([]string, 0, len(s.m))
	for crd, synced := range s.m {
		if !synced {
			u = append(u, crd)
		}
	}
	return u
}

// crdState contains the state of the CRDs inside the cluster.
type crdState struct {
	lock.Mutex

	// m is a map which maps the CRD name to its synced state in the cluster.
	// True means it exists, false means it doesn't exist.
	m map[string]bool
}

func newCRDState(m map[string]bool) crdState {
	return crdState{
		m: m,
	}
}

var (
	cnpCRD  = crdResourceName(v2.CNPName)
	ccnpCRD = crdResourceName(v2.CCNPName)
	cepCRD  = crdResourceName(v2.CEPName)
	cnCRD   = crdResourceName(v2.CNName)
	cidCRD  = crdResourceName(v2.CIDName)
	clrpCRD = crdResourceName(v2.CLRPName)
)

func crdResourceName(crd string) string {
	return "crd:" + crd
}

// newListWatchFromClient is a copy of the NewListWatchFromClient from the
// "k8s.io/client-go/tools/cache" package, with many alterations made to
// efficiently retrieve Cilium CRDs. If `specialHeader` is true, then efficient
// retrieval of CRDs is attempted which is only supported in K8s versions 1.14
// and below. Otherwise, a regular retrieval of the CRD object is attempted.
// Efficient retrieval is important because we don't want each agent to fetch
// the full CRDs across the cluster, because they potentially contain large
// validation schemas.
//
// This function also removes removes unnecessary calls from the upstream
// version that set the namespace and the resource when performing `Get`.
//
//   - If the resource was set, the following error was observed:
//     "customresourcedefinitions.apiextensions.k8s.io
//     "customresourcedefinitions" not found".
//   - If the namespace was set, the following error was observed:
//     "an empty namespace may not be set when a resource name is provided".
//
// The namespace problem can be worked around by using NamespaceIfScoped, but
// it's been omitted entirely here because it's equivalent in functionality.
func newListWatchFromClient(
	c cache.Getter,
	fieldSelector fields.Selector,
	specialHeader bool,
) *cache.ListWatch {
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fieldSelector.String()
	}

	listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		optionsModifier(&options)

		// This lister will retrieve the CRDs as a metav1.Table object if
		// `specialHeader` is true, otherwise this is a normal request.
		getter := c.Get()
		if specialHeader {
			// This is the same way that `kubectl get crds` returns them. In
			// the metav1.Table object, it contains cells, which are
			// metav1.PartialObjectMetadata objects containing the minimal
			// representation of an objects in K8s (in this case a CRD).  Once
			// the metav1.Table is fetched, it is converted into a
			// metav1.PartialObjectMetadataList which is what the controller
			// (informer) expects the object type to be. If we returned the
			// metav1.Table itself, the controller doesn't know how to handle
			// that object type because it is not a list type.
			getter = getter.SetHeader("Accept", tableHeader)

			t := &metav1.Table{}
			if err := getter.
				VersionedParams(&options, metav1.ParameterCodec).
				Do(context.TODO()).
				Into(t); err != nil {
				return nil, err
			}

			return tableToPomList(t), nil
		}

		crds := &v1beta1.CustomResourceDefinitionList{}
		if err := getter.
			VersionedParams(&options, metav1.ParameterCodec).
			Do(context.TODO()).
			Into(crds); err != nil {
			return nil, err
		}

		return crds, nil
	}
	watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {

		optionsModifier(&options)

		getter := c.Get()
		if specialHeader {
			// This watcher will retrieve each CRD that the lister has listed
			// as individual metav1.PartialObjectMetadata because it is
			// requesting the apiserver to return objects as such via the
			// "Accept" header.
			getter = getter.SetHeader("Accept", partialObjHeader)
		}

		options.Watch = true
		return getter.
			VersionedParams(&options, metav1.ParameterCodec).
			Watch(context.TODO())
	}
	return &cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

// tableToPomList converts a metav1.Table's cells into individual
// metav1.PartialObjectMetadata objects, and returns them all placed in a
// metav1.PartialObjectMetadataList.
//
// Note that K8s apiserver versions below 1.15 only have metav1beta1 version of
// Table and PartialObjectMetadata. However, because both types marshall the
// same to the same object because their fields have not changed (only a type
// version promotion), the code still works. Hence, we do not need different
// versions of this function to handle the different types. See
// https://github.com/kubernetes/kubernetes/pull/77136.
func tableToPomList(t *metav1.Table) *metav1.PartialObjectMetadataList {
	list := &metav1.PartialObjectMetadataList{
		TypeMeta: t.TypeMeta,
		ListMeta: t.ListMeta,
		Items:    make([]metav1.PartialObjectMetadata, 0, len(t.Rows)),
	}

	for _, row := range t.Rows {
		var pom metav1.PartialObjectMetadata
		if err := json.Unmarshal(row.Object.Raw, &pom); err != nil {
			log.WithError(err).Errorf("Converting metav1.Table to metav1.PartialObjectMetadata, unexpected type %T found, skipping",
				row.Object.Object)
			continue
		}

		list.Items = append(list.Items, pom)
	}

	return list
}

const (
	tableHeader      = "application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json"
	partialObjHeader = "application/json;as=PartialObjectMetadata;v=v1;g=meta.k8s.io,application/json;as=PartialObjectMetadata;v=v1beta1;g=meta.k8s.io,application/json"
)

// Get instantiates a GET request from the K8s REST client to retrieve CRDs. We
// define this getter because it's necessary to use the correct apiextensions
// client (v1 or v1beta1) in order to retrieve the CRDs in a
// backwards-compatible way. This implements the cache.Getter interface.
func (c *crdGetter) Get() *rest.Request {
	var req *rest.Request

	if k8sversion.Capabilities().APIExtensionsV1CRD {
		req = c.api.ApiextensionsV1().
			RESTClient().
			Get().
			Name("customresourcedefinitions")
	} else {
		req = c.api.ApiextensionsV1beta1().
			RESTClient().
			Get().
			Name("customresourcedefinitions")
	}

	return req
}

type crdGetter struct {
	api apiextclientset.Interface
}

func newCRDGetter(c apiextclientset.Interface) *crdGetter {
	return &crdGetter{api: c}
}
