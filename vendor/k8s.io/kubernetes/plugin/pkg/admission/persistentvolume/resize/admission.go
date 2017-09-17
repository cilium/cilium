/*
Copyright 2017 The Kubernetes Authors.

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

package resize

import (
	"fmt"
	"io"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	apihelper "k8s.io/kubernetes/pkg/api/helper"
	informers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	pvlister "k8s.io/kubernetes/pkg/client/listers/core/internalversion"
	storagelisters "k8s.io/kubernetes/pkg/client/listers/storage/internalversion"
	kubeapiserveradmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
)

const (
	// PluginName is the name of pvc resize admission plugin
	PluginName = "PersistentVolumeClaimResize"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		plugin := newPlugin()
		return plugin, nil
	})
}

var _ admission.Interface = &persistentVolumeClaimResize{}
var _ = kubeapiserveradmission.WantsInternalKubeInformerFactory(&persistentVolumeClaimResize{})

type persistentVolumeClaimResize struct {
	*admission.Handler

	pvLister pvlister.PersistentVolumeLister
	scLister storagelisters.StorageClassLister
}

func newPlugin() *persistentVolumeClaimResize {
	return &persistentVolumeClaimResize{
		Handler: admission.NewHandler(admission.Update),
	}
}

func (pvcr *persistentVolumeClaimResize) SetInternalKubeInformerFactory(f informers.SharedInformerFactory) {
	pvcInformer := f.Core().InternalVersion().PersistentVolumes()
	pvcr.pvLister = pvcInformer.Lister()
	scInformer := f.Storage().InternalVersion().StorageClasses()
	pvcr.scLister = scInformer.Lister()
	pvcr.SetReadyFunc(func() bool {
		return pvcInformer.Informer().HasSynced() && scInformer.Informer().HasSynced()
	})
}

// Validate ensures lister is set.
func (pvcr *persistentVolumeClaimResize) Validate() error {
	if pvcr.pvLister == nil {
		return fmt.Errorf("missing persistent volume lister")
	}
	if pvcr.scLister == nil {
		return fmt.Errorf("missing storageclass lister")
	}
	return nil
}

func (pvcr *persistentVolumeClaimResize) Admit(a admission.Attributes) error {
	if a.GetResource().GroupResource() != api.Resource("persistentvolumeclaims") {
		return nil
	}

	if len(a.GetSubresource()) != 0 {
		return nil
	}

	pvc, ok := a.GetObject().(*api.PersistentVolumeClaim)
	// if we can't convert then we don't handle this object so just return
	if !ok {
		return nil
	}
	oldPvc, ok := a.GetOldObject().(*api.PersistentVolumeClaim)
	if !ok {
		return nil
	}

	// Growing Persistent volumes is only allowed for PVCs for which their StorageClass
	// explicitly allows it
	if !pvcr.allowResize(pvc, oldPvc) {
		return admission.NewForbidden(a, fmt.Errorf("only dynamically provisioned pvc can be resized and "+
			"the storageclass that provisions the pvc must support resize"))
	}

	// volume plugin must support resize
	pv, err := pvcr.pvLister.Get(pvc.Spec.VolumeName)
	if err != nil {
		return nil
	}

	if !pvcr.checkVolumePlugin(pv) {
		return admission.NewForbidden(a, fmt.Errorf("volume plugin does not support resize"))
	}

	return nil
}

// Growing Persistent volumes is only allowed for PVCs for which their StorageClass
// explicitly allows it.
func (pvcr *persistentVolumeClaimResize) allowResize(pvc, oldPvc *api.PersistentVolumeClaim) bool {
	pvcStorageClass := apihelper.GetPersistentVolumeClaimClass(pvc)
	oldPvcStorageClass := apihelper.GetPersistentVolumeClaimClass(oldPvc)
	if pvcStorageClass == "" || oldPvcStorageClass == "" || pvcStorageClass != oldPvcStorageClass {
		return false
	}
	sc, err := pvcr.scLister.Get(pvcStorageClass)
	if err != nil {
		return false
	}
	if sc.AllowVolumeExpansion != nil {
		return *sc.AllowVolumeExpansion
	}
	return false
}

// checkVolumePlugin checks whether the volume plugin supports resize
func (pvcr *persistentVolumeClaimResize) checkVolumePlugin(pv *api.PersistentVolume) bool {
	if pv.Spec.Glusterfs != nil {
		return true
	}
	return false

}
