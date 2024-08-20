/*
Copyright 2018 The Kubernetes Authors.

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
	"go/ast"
	"go/types"
	"sort"
	"strings"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
	"sigs.k8s.io/controller-tools/pkg/version"
)

// The identifier for v1 CustomResourceDefinitions.
const v1 = "v1"

// The default CustomResourceDefinition version to generate.
const defaultVersion = v1

// +controllertools:marker:generateHelp

// Generator generates CustomResourceDefinition objects.
type Generator struct {
	// IgnoreUnexportedFields indicates that we should skip unexported fields.
	//
	// Left unspecified, the default is false.
	IgnoreUnexportedFields *bool `marker:",optional"`

	// AllowDangerousTypes allows types which are usually omitted from CRD generation
	// because they are not recommended.
	//
	// Currently the following additional types are allowed when this is true:
	// float32
	// float64
	//
	// Left unspecified, the default is false
	AllowDangerousTypes *bool `marker:",optional"`

	// MaxDescLen specifies the maximum description length for fields in CRD's OpenAPI schema.
	//
	// 0 indicates drop the description for all fields completely.
	// n indicates limit the description to at most n characters and truncate the description to
	// closest sentence boundary if it exceeds n characters.
	MaxDescLen *int `marker:",optional"`

	// CRDVersions specifies the target API versions of the CRD type itself to
	// generate. Defaults to v1.
	//
	// Currently, the only supported value is v1.
	//
	// The first version listed will be assumed to be the "default" version and
	// will not get a version suffix in the output filename.
	//
	// You'll need to use "v1" to get support for features like defaulting,
	// along with an API server that supports it (Kubernetes 1.16+).
	CRDVersions []string `marker:"crdVersions,optional"`

	// GenerateEmbeddedObjectMeta specifies if any embedded ObjectMeta in the CRD should be generated
	GenerateEmbeddedObjectMeta *bool `marker:",optional"`

	// HeaderFile specifies the header text (e.g. license) to prepend to generated files.
	HeaderFile string `marker:",optional"`

	// Year specifies the year to substitute for " YEAR" in the header file.
	Year string `marker:",optional"`

	// DeprecatedV1beta1CompatibilityPreserveUnknownFields indicates whether
	// or not we should turn off field pruning for this resource.
	//
	// Specifies spec.preserveUnknownFields value that is false and omitted by default.
	// This value can only be specified for CustomResourceDefinitions that were created with
	// `apiextensions.k8s.io/v1beta1`.
	//
	// The field can be set for compatiblity reasons, although strongly discouraged, resource
	// authors should move to a structural OpenAPI schema instead.
	//
	// See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#field-pruning
	// for more information about field pruning and v1beta1 resources compatibility.
	DeprecatedV1beta1CompatibilityPreserveUnknownFields *bool `marker:",optional"`
}

func (Generator) CheckFilter() loader.NodeFilter {
	return filterTypesForCRDs
}
func (Generator) RegisterMarkers(into *markers.Registry) error {
	return crdmarkers.Register(into)
}

// transformRemoveCRDStatus ensures we do not write the CRD status field.
func transformRemoveCRDStatus(obj map[string]interface{}) error {
	delete(obj, "status")
	return nil
}

// transformPreserveUnknownFields adds spec.preserveUnknownFields=value.
func transformPreserveUnknownFields(value bool) func(map[string]interface{}) error {
	return func(obj map[string]interface{}) error {
		if spec, ok := obj["spec"].(map[interface{}]interface{}); ok {
			spec["preserveUnknownFields"] = value
		}
		return nil
	}
}

func (g Generator) Generate(ctx *genall.GenerationContext) error {
	parser := &Parser{
		Collector: ctx.Collector,
		Checker:   ctx.Checker,
		// Perform defaulting here to avoid ambiguity later
		IgnoreUnexportedFields: g.IgnoreUnexportedFields != nil && *g.IgnoreUnexportedFields,
		AllowDangerousTypes:    g.AllowDangerousTypes != nil && *g.AllowDangerousTypes,
		// Indicates the parser on whether to register the ObjectMeta type or not
		GenerateEmbeddedObjectMeta: g.GenerateEmbeddedObjectMeta != nil && *g.GenerateEmbeddedObjectMeta,
	}

	AddKnownTypes(parser)
	for _, root := range ctx.Roots {
		parser.NeedPackage(root)
	}

	metav1Pkg := FindMetav1(ctx.Roots)
	if metav1Pkg == nil {
		// no objects in the roots, since nothing imported metav1
		return nil
	}

	// TODO: allow selecting a specific object
	kubeKinds := FindKubeKinds(parser, metav1Pkg)
	if len(kubeKinds) == 0 {
		// no objects in the roots
		return nil
	}

	crdVersions := g.CRDVersions

	if len(crdVersions) == 0 {
		crdVersions = []string{defaultVersion}
	}

	var headerText string

	if g.HeaderFile != "" {
		headerBytes, err := ctx.ReadFile(g.HeaderFile)
		if err != nil {
			return err
		}
		headerText = string(headerBytes)
	}
	headerText = strings.ReplaceAll(headerText, " YEAR", " "+g.Year)

	yamlOpts := []*genall.WriteYAMLOptions{
		genall.WithTransform(transformRemoveCRDStatus),
		genall.WithTransform(genall.TransformRemoveCreationTimestamp),
	}
	if g.DeprecatedV1beta1CompatibilityPreserveUnknownFields != nil {
		yamlOpts = append(yamlOpts, genall.WithTransform(transformPreserveUnknownFields(*g.DeprecatedV1beta1CompatibilityPreserveUnknownFields)))
	}

	for _, groupKind := range kubeKinds {
		parser.NeedCRDFor(groupKind, g.MaxDescLen)
		crdRaw := parser.CustomResourceDefinitions[groupKind]
		addAttribution(&crdRaw)

		// Prevent the top level metadata for the CRD to be generate regardless of the intention in the arguments
		FixTopLevelMetadata(crdRaw)

		versionedCRDs := make([]interface{}, len(crdVersions))
		for i, ver := range crdVersions {
			conv, err := AsVersion(crdRaw, schema.GroupVersion{Group: apiext.SchemeGroupVersion.Group, Version: ver})
			if err != nil {
				return err
			}
			versionedCRDs[i] = conv
		}

		for i, crd := range versionedCRDs {
			removeDescriptionFromMetadata(crd.(*apiext.CustomResourceDefinition))
			var fileName string
			if i == 0 {
				fileName = fmt.Sprintf("%s_%s.yaml", crdRaw.Spec.Group, crdRaw.Spec.Names.Plural)
			} else {
				fileName = fmt.Sprintf("%s_%s.%s.yaml", crdRaw.Spec.Group, crdRaw.Spec.Names.Plural, crdVersions[i])
			}
			if err := ctx.WriteYAML(fileName, headerText, []interface{}{crd}, yamlOpts...); err != nil {
				return err
			}
		}
	}

	return nil
}

func removeDescriptionFromMetadata(crd *apiext.CustomResourceDefinition) {
	for _, versionSpec := range crd.Spec.Versions {
		if versionSpec.Schema != nil {
			removeDescriptionFromMetadataProps(versionSpec.Schema.OpenAPIV3Schema)
		}
	}
}

func removeDescriptionFromMetadataProps(v *apiext.JSONSchemaProps) {
	if m, ok := v.Properties["metadata"]; ok {
		meta := &m
		if meta.Description != "" {
			meta.Description = ""
			v.Properties["metadata"] = m
		}
	}
}

// FixTopLevelMetadata resets the schema for the top-level metadata field which is needed for CRD validation
func FixTopLevelMetadata(crd apiext.CustomResourceDefinition) {
	for _, v := range crd.Spec.Versions {
		if v.Schema != nil && v.Schema.OpenAPIV3Schema != nil && v.Schema.OpenAPIV3Schema.Properties != nil {
			schemaProperties := v.Schema.OpenAPIV3Schema.Properties
			if _, ok := schemaProperties["metadata"]; ok {
				schemaProperties["metadata"] = apiext.JSONSchemaProps{Type: "object"}
			}
		}
	}
}

// addAttribution adds attribution info to indicate controller-gen tool was used
// to generate this CRD definition along with the version info.
func addAttribution(crd *apiext.CustomResourceDefinition) {
	if crd.ObjectMeta.Annotations == nil {
		crd.ObjectMeta.Annotations = map[string]string{}
	}
	crd.ObjectMeta.Annotations["controller-gen.kubebuilder.io/version"] = version.Version()
}

// FindMetav1 locates the actual package representing metav1 amongst
// the imports of the roots.
func FindMetav1(roots []*loader.Package) *loader.Package {
	for _, root := range roots {
		pkg := root.Imports()["k8s.io/apimachinery/pkg/apis/meta/v1"]
		if pkg != nil {
			return pkg
		}
	}
	return nil
}

// FindKubeKinds locates all types that contain TypeMeta and ObjectMeta
// (and thus may be a Kubernetes object), and returns the corresponding
// group-kinds.
func FindKubeKinds(parser *Parser, metav1Pkg *loader.Package) []schema.GroupKind {
	// TODO(directxman12): technically, we should be finding metav1 per-package
	kubeKinds := map[schema.GroupKind]struct{}{}
	for typeIdent, info := range parser.Types {
		hasObjectMeta := false
		hasTypeMeta := false

		pkg := typeIdent.Package
		pkg.NeedTypesInfo()
		typesInfo := pkg.TypesInfo

		for _, field := range info.Fields {
			if field.Name != "" {
				// type and object meta are embedded,
				// so they can't be this
				continue
			}

			fieldType := typesInfo.TypeOf(field.RawField.Type)
			namedField, isNamed := fieldType.(*types.Named)
			if !isNamed {
				// ObjectMeta and TypeMeta are named types
				continue
			}
			if namedField.Obj().Pkg() == nil {
				// Embedded non-builtin universe type (specifically, it's probably `error`),
				// so it can't be ObjectMeta or TypeMeta
				continue
			}
			fieldPkgPath := loader.NonVendorPath(namedField.Obj().Pkg().Path())
			fieldPkg := pkg.Imports()[fieldPkgPath]

			// Compare the metav1 package by ID and not by the actual instance
			// of the object. The objects in memory could be different due to
			// loading from different root paths, even when they both refer to
			// the same metav1 package.
			if fieldPkg == nil || fieldPkg.ID != metav1Pkg.ID {
				continue
			}

			switch namedField.Obj().Name() {
			case "ObjectMeta":
				hasObjectMeta = true
			case "TypeMeta":
				hasTypeMeta = true
			}
		}

		if !hasObjectMeta || !hasTypeMeta {
			continue
		}

		groupKind := schema.GroupKind{
			Group: parser.GroupVersions[pkg].Group,
			Kind:  typeIdent.Name,
		}
		kubeKinds[groupKind] = struct{}{}
	}

	groupKindList := make([]schema.GroupKind, 0, len(kubeKinds))
	for groupKind := range kubeKinds {
		groupKindList = append(groupKindList, groupKind)
	}
	sort.Slice(groupKindList, func(i, j int) bool {
		return groupKindList[i].String() < groupKindList[j].String()
	})

	return groupKindList
}

// filterTypesForCRDs filters out all nodes that aren't used in CRD generation,
// like interfaces and struct fields without JSON tag.
func filterTypesForCRDs(node ast.Node) bool {
	switch node := node.(type) {
	case *ast.InterfaceType:
		// skip interfaces, we never care about references in them
		return false
	case *ast.StructType:
		return true
	case *ast.Field:
		_, hasTag := loader.ParseAstTag(node.Tag).Lookup("json")
		// fields without JSON tags mean we have custom serialization,
		// so only visit fields with tags.
		return hasTag
	default:
		return true
	}
}
