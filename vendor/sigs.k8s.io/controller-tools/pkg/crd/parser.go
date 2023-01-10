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

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// TypeIdent represents some type in a Package.
type TypeIdent struct {
	Package *loader.Package
	Name    string
}

func (t TypeIdent) String() string {
	return fmt.Sprintf("%q.%s", t.Package.ID, t.Name)
}

// PackageOverride overrides the loading of some package
// (potentially setting custom schemata, etc).  It must
// call AddPackage if it wants to continue with the default
// loading behavior.
type PackageOverride func(p *Parser, pkg *loader.Package)

// Parser knows how to parse out CRD information and generate
// OpenAPI schemata from some collection of types and markers.
// Most methods on Parser cache their results automatically,
// and thus may be called any number of times.
type Parser struct {
	Collector *markers.Collector

	// Types contains the known TypeInfo for this parser.
	Types map[TypeIdent]*markers.TypeInfo
	// Schemata contains the known OpenAPI JSONSchemata for this parser.
	Schemata map[TypeIdent]apiext.JSONSchemaProps
	// GroupVersions contains the known group-versions of each package in this parser.
	GroupVersions map[*loader.Package]schema.GroupVersion
	// CustomResourceDefinitions contains the known CustomResourceDefinitions for types in this parser.
	CustomResourceDefinitions map[schema.GroupKind]apiext.CustomResourceDefinition
	// FlattenedSchemata contains fully flattened schemata for use in building
	// CustomResourceDefinition validation.  Each schema has been flattened by the flattener,
	// and then embedded fields have been flattened with FlattenEmbedded.
	FlattenedSchemata map[TypeIdent]apiext.JSONSchemaProps

	// PackageOverrides indicates that the loading of any package with
	// the given path should be handled by the given overrider.
	PackageOverrides map[string]PackageOverride

	// checker stores persistent partial type-checking/reference-traversal information.
	Checker *loader.TypeChecker
	// packages marks packages as loaded, to avoid re-loading them.
	packages map[*loader.Package]struct{}

	flattener *Flattener

	// AllowDangerousTypes controls the handling of non-recommended types such as float. If
	// false (the default), these types are not supported.
	// There is a continuum here:
	//    1. Types that are always supported.
	//    2. Types that are allowed by default, but not recommended (warning emitted when they are encountered as per PR #443).
	//       Possibly they are allowed by default for historical reasons and may even be "on their way out" at some point in the future.
	//    3. Types that are not allowed by default, not recommended, but there are some legitimate reasons to need them in certain corner cases.
	//       Possibly these types should also emit a warning as per PR #443 even when they are "switched on" (an integration point between
	//       this feature and #443 if desired). This is the category that this flag deals with.
	//    4. Types that are not allowed and will not be allowed, possibly because it just "doesn't make sense" or possibly
	//       because the implementation is too difficult/clunky to promote them to category 3.
	// TODO: Should we have a more formal mechanism for putting "type patterns" in each of the above categories?
	AllowDangerousTypes bool

	// GenerateEmbeddedObjectMeta specifies if any embedded ObjectMeta should be generated
	GenerateEmbeddedObjectMeta bool
}

func (p *Parser) init() {
	if p.packages == nil {
		p.packages = make(map[*loader.Package]struct{})
	}
	if p.flattener == nil {
		p.flattener = &Flattener{
			Parser: p,
		}
	}
	if p.Schemata == nil {
		p.Schemata = make(map[TypeIdent]apiext.JSONSchemaProps)
	}
	if p.Types == nil {
		p.Types = make(map[TypeIdent]*markers.TypeInfo)
	}
	if p.PackageOverrides == nil {
		p.PackageOverrides = make(map[string]PackageOverride)
	}
	if p.GroupVersions == nil {
		p.GroupVersions = make(map[*loader.Package]schema.GroupVersion)
	}
	if p.CustomResourceDefinitions == nil {
		p.CustomResourceDefinitions = make(map[schema.GroupKind]apiext.CustomResourceDefinition)
	}
	if p.FlattenedSchemata == nil {
		p.FlattenedSchemata = make(map[TypeIdent]apiext.JSONSchemaProps)
	}
}

// indexTypes loads all types in the package into Types.
func (p *Parser) indexTypes(pkg *loader.Package) {
	// autodetect
	pkgMarkers, err := markers.PackageMarkers(p.Collector, pkg)
	if err != nil {
		pkg.AddError(err)
	} else {
		if skipPkg := pkgMarkers.Get("kubebuilder:skip"); skipPkg != nil {
			return
		}
		if nameVal := pkgMarkers.Get("groupName"); nameVal != nil {
			versionVal := pkg.Name // a reasonable guess
			if versionMarker := pkgMarkers.Get("versionName"); versionMarker != nil {
				versionVal = versionMarker.(string)
			}

			p.GroupVersions[pkg] = schema.GroupVersion{
				Version: versionVal,
				Group:   nameVal.(string),
			}
		}
	}

	if err := markers.EachType(p.Collector, pkg, func(info *markers.TypeInfo) {
		ident := TypeIdent{
			Package: pkg,
			Name:    info.Name,
		}

		p.Types[ident] = info
	}); err != nil {
		pkg.AddError(err)
	}
}

// LookupType fetches type info from Types.
func (p *Parser) LookupType(pkg *loader.Package, name string) *markers.TypeInfo {
	return p.Types[TypeIdent{Package: pkg, Name: name}]
}

// NeedSchemaFor indicates that a schema should be generated for the given type.
func (p *Parser) NeedSchemaFor(typ TypeIdent) {
	p.init()

	p.NeedPackage(typ.Package)
	if _, knownSchema := p.Schemata[typ]; knownSchema {
		return
	}

	info, knownInfo := p.Types[typ]
	if !knownInfo {
		typ.Package.AddError(fmt.Errorf("unknown type %s", typ))
		return
	}

	// avoid tripping recursive schemata, like ManagedFields, by adding an empty WIP schema
	p.Schemata[typ] = apiext.JSONSchemaProps{}

	schemaCtx := newSchemaContext(typ.Package, p, p.AllowDangerousTypes)
	ctxForInfo := schemaCtx.ForInfo(info)

	pkgMarkers, err := markers.PackageMarkers(p.Collector, typ.Package)
	if err != nil {
		typ.Package.AddError(err)
	}
	ctxForInfo.PackageMarkers = pkgMarkers

	schema := infoToSchema(ctxForInfo)

	p.Schemata[typ] = *schema
}

func (p *Parser) NeedFlattenedSchemaFor(typ TypeIdent) {
	p.init()

	if _, knownSchema := p.FlattenedSchemata[typ]; knownSchema {
		return
	}

	p.NeedSchemaFor(typ)
	partialFlattened := p.flattener.FlattenType(typ)
	fullyFlattened := FlattenEmbedded(partialFlattened, typ.Package)

	p.FlattenedSchemata[typ] = *fullyFlattened
}

// NeedCRDFor lives off in spec.go

// AddPackage indicates that types and type-checking information is needed
// for the the given package, *ignoring* overrides.
// Generally, consumers should call NeedPackage, while PackageOverrides should
// call AddPackage to continue with the normal loading procedure.
func (p *Parser) AddPackage(pkg *loader.Package) {
	p.init()
	if _, checked := p.packages[pkg]; checked {
		return
	}
	p.indexTypes(pkg)
	p.Checker.Check(pkg)
	p.packages[pkg] = struct{}{}
}

// NeedPackage indicates that types and type-checking information
// is needed for the given package.
func (p *Parser) NeedPackage(pkg *loader.Package) {
	p.init()
	if _, checked := p.packages[pkg]; checked {
		return
	}
	// overrides are going to be written without vendor.  This is why we index by the actual
	// object when we can.
	if override, overridden := p.PackageOverrides[loader.NonVendorPath(pkg.PkgPath)]; overridden {
		override(p, pkg)
		p.packages[pkg] = struct{}{}
		return
	}
	p.AddPackage(pkg)
}
