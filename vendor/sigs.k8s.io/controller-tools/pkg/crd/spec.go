/*
Copyright 2019 The Kubernetes Authors.

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
package crd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gobuffalo/flect"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-tools/pkg/loader"
)

// SpecMarker is a marker that knows how to apply itself to a particular
// version in a CRD.
type SpecMarker interface {
	// ApplyToCRD applies this marker to the given CRD, in the given version
	// within that CRD.  It's called after everything else in the CRD is populated.
	ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error
}

// NeedCRDFor requests the full CRD for the given group-kind.  It requires
// that the packages containing the Go structs for that CRD have already
// been loaded with NeedPackage.
func (p *Parser) NeedCRDFor(groupKind schema.GroupKind, maxDescLen *int) {
	p.init()

	if _, exists := p.CustomResourceDefinitions[groupKind]; exists {
		return
	}

	var packages []*loader.Package
	for pkg, gv := range p.GroupVersions {
		if gv.Group != groupKind.Group {
			continue
		}
		packages = append(packages, pkg)
	}

	defaultPlural := flect.Pluralize(strings.ToLower(groupKind.Kind))
	crd := apiext.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiext.SchemeGroupVersion.String(),
			Kind:       "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultPlural + "." + groupKind.Group,
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group: groupKind.Group,
			Names: apiext.CustomResourceDefinitionNames{
				Kind:     groupKind.Kind,
				ListKind: groupKind.Kind + "List",
				Plural:   defaultPlural,
				Singular: strings.ToLower(groupKind.Kind),
			},
			Scope: apiext.NamespaceScoped,
		},
	}

	for _, pkg := range packages {
		typeIdent := TypeIdent{Package: pkg, Name: groupKind.Kind}
		typeInfo := p.Types[typeIdent]
		if typeInfo == nil {
			continue
		}
		p.NeedFlattenedSchemaFor(typeIdent)
		fullSchema := p.FlattenedSchemata[typeIdent]
		fullSchema = *fullSchema.DeepCopy() // don't mutate the cache (we might be truncating description, etc)
		if maxDescLen != nil {
			TruncateDescription(&fullSchema, *maxDescLen)
		}
		ver := apiext.CustomResourceDefinitionVersion{
			Name:   p.GroupVersions[pkg].Version,
			Served: true,
			Schema: &apiext.CustomResourceValidation{
				OpenAPIV3Schema: &fullSchema, // fine to take a reference since we deepcopy above
			},
		}
		crd.Spec.Versions = append(crd.Spec.Versions, ver)
	}

	// markers are applied *after* initial generation of objects
	for _, pkg := range packages {
		typeIdent := TypeIdent{Package: pkg, Name: groupKind.Kind}
		typeInfo := p.Types[typeIdent]
		if typeInfo == nil {
			continue
		}
		ver := p.GroupVersions[pkg].Version

		for _, markerVals := range typeInfo.Markers {
			for _, val := range markerVals {
				crdMarker, isCrdMarker := val.(SpecMarker)
				if !isCrdMarker {
					continue
				}
				if err := crdMarker.ApplyToCRD(&crd.Spec, ver); err != nil {
					pkg.AddError(loader.ErrFromNode(err /* an okay guess */, typeInfo.RawSpec))
				}
			}
		}
	}

	// fix the name if the plural was changed (this is the form the name *has* to take, so no harm in changing it).
	crd.Name = crd.Spec.Names.Plural + "." + groupKind.Group

	// nothing to actually write
	if len(crd.Spec.Versions) == 0 {
		return
	}

	// it is necessary to make sure the order of CRD versions in crd.Spec.Versions is stable and explicitly set crd.Spec.Version.
	// Otherwise, crd.Spec.Version may point to different CRD versions across different runs.
	sort.Slice(crd.Spec.Versions, func(i, j int) bool { return crd.Spec.Versions[i].Name < crd.Spec.Versions[j].Name })

	// make sure we have *a* storage version
	// (default it if we only have one, otherwise, bail)
	if len(crd.Spec.Versions) == 1 {
		crd.Spec.Versions[0].Storage = true
	}

	hasStorage := false
	for _, ver := range crd.Spec.Versions {
		if ver.Storage {
			hasStorage = true
			break
		}
	}
	if !hasStorage {
		// just add the error to the first relevant package for this CRD,
		// since there's no specific error location
		packages[0].AddError(fmt.Errorf("CRD for %s has no storage version", groupKind))
	}

	served := false
	for _, ver := range crd.Spec.Versions {
		if ver.Served {
			served = true
			break
		}
	}
	if !served {
		// just add the error to the first relevant package for this CRD,
		// since there's no specific error location
		packages[0].AddError(fmt.Errorf("CRD for %s with version(s) %v does not serve any version", groupKind, crd.Spec.Versions))
	}

	// NB(directxman12): CRD's status doesn't have omitempty markers, which means things
	// get serialized as null, which causes the validator to freak out.  Manually set
	// these to empty till we get a better solution.
	crd.Status.Conditions = []apiext.CustomResourceDefinitionCondition{}
	crd.Status.StoredVersions = []string{}

	p.CustomResourceDefinitions[groupKind] = crd
}
