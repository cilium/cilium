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
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"sigs.k8s.io/controller-tools/pkg/loader"
)

// KnownPackages overrides types in some comment packages that have custom validation
// but don't have validation markers on them (since they're from core Kubernetes).
var KnownPackages = map[string]PackageOverride{
	"k8s.io/api/core/v1": func(p *Parser, pkg *loader.Package) {
		// Explicit defaulting for the corev1.Protocol type in lieu of https://github.com/kubernetes/enhancements/pull/1928
		p.Schemata[TypeIdent{Name: "Protocol", Package: pkg}] = apiext.JSONSchemaProps{
			Type:    "string",
			Default: &apiext.JSON{Raw: []byte(`"TCP"`)},
		}
		p.AddPackage(pkg)
	},

	"k8s.io/apimachinery/pkg/apis/meta/v1": func(p *Parser, pkg *loader.Package) {
		// ObjectMeta is managed by the Kubernetes API server, so no need to
		// generate validation for it.
		p.Schemata[TypeIdent{Name: "ObjectMeta", Package: pkg}] = apiext.JSONSchemaProps{
			Type: "object",
		}
		p.Schemata[TypeIdent{Name: "Time", Package: pkg}] = apiext.JSONSchemaProps{
			Type:   "string",
			Format: "date-time",
		}
		p.Schemata[TypeIdent{Name: "MicroTime", Package: pkg}] = apiext.JSONSchemaProps{
			Type:   "string",
			Format: "date-time",
		}
		p.Schemata[TypeIdent{Name: "Duration", Package: pkg}] = apiext.JSONSchemaProps{
			// TODO(directxman12): regexp validation for this (or get kube to support it as a format value)
			Type: "string",
		}
		p.Schemata[TypeIdent{Name: "Fields", Package: pkg}] = apiext.JSONSchemaProps{
			// this is a recursive structure that can't be flattened or, for that matter, properly generated.
			// so just treat it as an arbitrary map
			Type:                 "object",
			AdditionalProperties: &apiext.JSONSchemaPropsOrBool{Allows: true},
		}
		p.AddPackage(pkg) // get the rest of the types
	},

	"k8s.io/apimachinery/pkg/api/resource": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "Quantity", Package: pkg}] = apiext.JSONSchemaProps{
			// TODO(directxman12): regexp validation for this (or get kube to support it as a format value)
			XIntOrString: true,
			AnyOf: []apiext.JSONSchemaProps{
				{Type: "integer"},
				{Type: "string"},
			},
			Pattern: "^(\\+|-)?(([0-9]+(\\.[0-9]*)?)|(\\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\\+|-)?(([0-9]+(\\.[0-9]*)?)|(\\.[0-9]+))))?$",
		}
		// No point in calling AddPackage, this is the sole inhabitant
	},

	"k8s.io/apimachinery/pkg/runtime": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "RawExtension", Package: pkg}] = apiext.JSONSchemaProps{
			// TODO(directxman12): regexp validation for this (or get kube to support it as a format value)
			Type: "object",
		}
		p.AddPackage(pkg) // get the rest of the types
	},

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "Unstructured", Package: pkg}] = apiext.JSONSchemaProps{
			Type: "object",
		}
		p.AddPackage(pkg) // get the rest of the types
	},

	"k8s.io/apimachinery/pkg/util/intstr": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "IntOrString", Package: pkg}] = apiext.JSONSchemaProps{
			XIntOrString: true,
			AnyOf: []apiext.JSONSchemaProps{
				{Type: "integer"},
				{Type: "string"},
			},
		}
		// No point in calling AddPackage, this is the sole inhabitant
	},

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "JSON", Package: pkg}] = apiext.JSONSchemaProps{
			XPreserveUnknownFields: boolPtr(true),
		}
		p.AddPackage(pkg) // get the rest of the types
	},
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1": func(p *Parser, pkg *loader.Package) {
		p.Schemata[TypeIdent{Name: "JSON", Package: pkg}] = apiext.JSONSchemaProps{
			XPreserveUnknownFields: boolPtr(true),
		}
		p.AddPackage(pkg) // get the rest of the types
	},
}

func boolPtr(b bool) *bool {
	return &b
}

// AddKnownTypes registers the packages overrides in KnownPackages with the given parser.
func AddKnownTypes(parser *Parser) {
	// ensure everything is there before adding to PackageOverrides
	// TODO(directxman12): this is a bit of a hack, maybe just use constructors?
	parser.init()
	for pkgName, override := range KnownPackages {
		parser.PackageOverrides[pkgName] = override
	}
}
