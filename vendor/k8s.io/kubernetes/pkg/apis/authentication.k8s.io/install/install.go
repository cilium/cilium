/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

// Package install installs the experimental API group, making it available as
// an option to all of the API encoding/decoding machinery.
package install

import (
	"fmt"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/meta"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apimachinery"
	"k8s.io/kubernetes/pkg/apimachinery/registered"
	"k8s.io/kubernetes/pkg/apis/authentication.k8s.io"
	"k8s.io/kubernetes/pkg/apis/authentication.k8s.io/v1beta1"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/sets"
)

const importPrefix = "k8s.io/kubernetes/pkg/apis/authentication.k8s.io"

var accessor = meta.NewAccessor()

// availableVersions lists all known external versions for this group from most preferred to least preferred
var availableVersions = []unversioned.GroupVersion{v1beta1.SchemeGroupVersion}

func init() {
	registered.RegisterVersions(availableVersions)
	externalVersions := []unversioned.GroupVersion{}
	for _, v := range availableVersions {
		if registered.IsAllowedVersion(v) {
			externalVersions = append(externalVersions, v)
		}
	}
	if len(externalVersions) == 0 {
		glog.V(4).Infof("No version is registered for group %v", authentication.GroupName)
		return
	}

	if err := registered.EnableVersions(externalVersions...); err != nil {
		glog.V(4).Infof("%v", err)
		return
	}
	if err := enableVersions(externalVersions); err != nil {
		glog.V(4).Infof("%v", err)
		return
	}
}

// TODO: enableVersions should be centralized rather than spread in each API
// group.
// We can combine registered.RegisterVersions, registered.EnableVersions and
// registered.RegisterGroup once we have moved enableVersions there.
func enableVersions(externalVersions []unversioned.GroupVersion) error {
	addVersionsToScheme(externalVersions...)
	preferredExternalVersion := externalVersions[0]

	groupMeta := apimachinery.GroupMeta{
		GroupVersion:  preferredExternalVersion,
		GroupVersions: externalVersions,
		RESTMapper:    newRESTMapper(externalVersions),
		SelfLinker:    runtime.SelfLinker(accessor),
		InterfacesFor: interfacesFor,
	}

	if err := registered.RegisterGroup(groupMeta); err != nil {
		return err
	}
	api.RegisterRESTMapper(groupMeta.RESTMapper)
	return nil
}

func addVersionsToScheme(externalVersions ...unversioned.GroupVersion) {
	// add the internal version to Scheme
	authentication.AddToScheme(api.Scheme)
	// add the enabled external versions to Scheme
	for _, v := range externalVersions {
		if !registered.IsEnabledVersion(v) {
			glog.Errorf("Version %s is not enabled, so it will not be added to the Scheme.", v)
			continue
		}
		switch v {
		case v1beta1.SchemeGroupVersion:
			v1beta1.AddToScheme(api.Scheme)
		}
	}
}

func newRESTMapper(externalVersions []unversioned.GroupVersion) meta.RESTMapper {
	rootScoped := sets.NewString("TokenReview")
	ignoredKinds := sets.NewString()
	return api.NewDefaultRESTMapper(externalVersions, interfacesFor, importPrefix, ignoredKinds, rootScoped)
}

func interfacesFor(version unversioned.GroupVersion) (*meta.VersionInterfaces, error) {
	switch version {
	case v1beta1.SchemeGroupVersion:
		return &meta.VersionInterfaces{
			ObjectConvertor:  api.Scheme,
			MetadataAccessor: accessor,
		}, nil
	default:
		g, _ := registered.Group(authentication.GroupName)
		return nil, fmt.Errorf("unsupported storage version: %s (valid: %v)", version, g.GroupVersions)
	}
}
