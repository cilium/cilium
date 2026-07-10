/*
Copyright The Kubernetes Authors.

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

package applyconfiguration

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kube-openapi/pkg/util"

	"sigs.k8s.io/controller-tools/pkg/crd"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// buildOpenAPISchema generates a minimal OpenAPI v2 Swagger document containing
// schemas for every type referenced by root CRD types in the package. Types are
// represented as separate definitions with $ref links between them, producing
// namedType entries in the structured-merge-diff schema. The definition keys
// match the convention used by code-generator (via kube-openapi
// util.ToRESTFriendlyName).
func (ctx *ObjectGenCtx) buildOpenAPISchema(root *loader.Package, gv schema.GroupVersion) (string, error) {
	p := &crd.Parser{
		Collector:              ctx.Collector,
		Checker:                ctx.Checker,
		AllowDangerousTypes:    true,
		IgnoreUnexportedFields: true,
	}
	crd.AddKnownTypes(p)

	// Wrap the metav1 package override so that ObjectMeta is generated from
	// Go source (with full fields and list-type markers) instead of using the
	// CRD-specific 5-field allow-list. The original KnownPackages override
	// sets Time/Duration/Fields schemas and calls AddPackage (populating
	// p.Types). By deleting the cached ObjectMeta schema afterwards, NeedSchemaFor
	// will regenerate it from the TypeInfo already loaded in p.Types, producing
	// the complete schema.
	const metav1PkgPath = "k8s.io/apimachinery/pkg/apis/meta/v1"
	if origOverride, ok := p.PackageOverrides[metav1PkgPath]; ok {
		p.PackageOverrides[metav1PkgPath] = func(parser *crd.Parser, pkg *loader.Package) {
			origOverride(parser, pkg)
			delete(parser.Schemata, crd.TypeIdent{Name: "ObjectMeta", Package: pkg})
		}
	}

	p.NeedPackage(root)

	// Collect root CRD type names and trigger schema generation for all
	// transitive types. NeedSchemaFor (not NeedFlattenedSchemaFor) preserves
	// $ref references in the schemas.
	crdTypeSet := make(map[string]bool)
	if err := markers.EachType(ctx.Collector, root, func(info *markers.TypeInfo) {
		if !isCRD(info) {
			return
		}
		crdTypeSet[info.Name] = true
		p.NeedSchemaFor(crd.TypeIdent{Package: root, Name: info.Name})
	}); err != nil {
		return "", err
	}
	if len(crdTypeSet) == 0 {
		return "", nil
	}

	// Build pkgByPath map for resolving cross-package refs.
	pkgByPath := make(map[string]*loader.Package)
	for ident := range p.Schemata {
		if ident.Package != nil {
			pkgByPath[ident.Package.PkgPath] = ident.Package
		}
	}

	// Process every type in Schemata into a swagger definition.
	definitions := make(map[string]any)
	for ident, s := range p.Schemata {
		schema := s.DeepCopy()

		// Resolve $ref entries inside AllOf (embedded structs) so that
		// FlattenEmbedded can merge their properties. $ref in Properties,
		// Items, etc. are preserved for namedType generation.
		if err := resolveAllOfRefs(schema, ident.Package, p, pkgByPath); err != nil {
			return "", fmt.Errorf("failed to resolve allOf refs for %s: %w", ident.Name, err)
		}
		schema = crd.FlattenEmbedded(schema, ident.Package)

		// Convert internal $ref format to swagger definition keys.
		convertRefs(schema, ident.Package)

		schemaJSON, err := json.Marshal(schema)
		if err != nil {
			return "", fmt.Errorf("failed to marshal schema for %s: %w", ident.Name, err)
		}
		var schemaMap map[string]any
		if err := json.Unmarshal(schemaJSON, &schemaMap); err != nil {
			return "", fmt.Errorf("failed to unmarshal schema for %s: %w", ident.Name, err)
		}

		// Clean the schema to be OpenAPI v2 compatible.
		sanitizeForOpenAPIV2(schemaMap)

		pkgPath := ""
		if ident.Package != nil {
			pkgPath = ident.Package.PkgPath
		}
		key := util.ToRESTFriendlyName(pkgPath + "." + ident.Name)

		// Add GVK annotation only to root CRD type definitions.
		if ident.Package == root && crdTypeSet[ident.Name] {
			schemaMap["x-kubernetes-group-version-kind"] = []any{
				map[string]any{
					"group":   gv.Group,
					"version": gv.Version,
					"kind":    ident.Name,
				},
			}
		}

		definitions[key] = schemaMap
	}

	resolveRefDefinitions(definitions)

	swagger := map[string]any{
		"swagger": "2.0",
		"info": map[string]any{
			"title":   "Kubernetes CRD Swagger",
			"version": "v0.1.0",
		},
		"paths":       map[string]any{},
		"definitions": definitions,
	}

	swaggerJSON, err := json.Marshal(swagger)
	if err != nil {
		return "", fmt.Errorf("failed to marshal swagger document: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "openapi-schema-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(swaggerJSON); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write swagger document: %w", err)
	}

	return tmpFile.Name(), nil
}

// resolveAllOfRefs walks the schema and resolves $ref entries inside AllOf slices
// by replacing them with the referenced type's schema (deep-copied). This preserves
// $ref in other locations (Properties, Items, etc.) while making AllOf entries ready
// for flattening by FlattenEmbedded.
//
// We only resolve AllOfs, as nullable, anyOf, oneOf and not are dropped, since swagger
// v2 doesn't support them.
func resolveAllOfRefs(schema *apiextensionsv1.JSONSchemaProps, contextPkg *loader.Package, p *crd.Parser, pkgByPath map[string]*loader.Package) error {
	if schema == nil {
		return nil
	}

	for i := range schema.AllOf {
		entry := &schema.AllOf[i]
		if entry.Ref != nil && len(*entry.Ref) > 0 {
			typeName, pkgPath, err := crd.RefParts(*entry.Ref)
			if err != nil {
				return fmt.Errorf("failed to parse ref %q: %w", *entry.Ref, err)
			}
			pkg := contextPkg
			if pkgPath != "" {
				pkg = pkgByPath[pkgPath]
			}
			if pkg == nil {
				return fmt.Errorf("package %q not found for ref %q", pkgPath, *entry.Ref)
			}
			refIdent := crd.TypeIdent{Package: pkg, Name: typeName}
			refSchema, found := p.Schemata[refIdent]
			if !found {
				return fmt.Errorf("schema not found for type %q in package %q", typeName, pkg.PkgPath)
			}
			resolved := refSchema.DeepCopy()
			// Recurse into the resolved schema to handle nested embeddings.
			if err := resolveAllOfRefs(resolved, pkg, p, pkgByPath); err != nil {
				return err
			}
			schema.AllOf[i] = *resolved
		} else {
			// Recurse into non-ref AllOf entries.
			if err := resolveAllOfRefs(entry, contextPkg, p, pkgByPath); err != nil {
				return err
			}
		}
	}

	// Recurse into other schema locations that may contain nested AllOf refs.
	for k, v := range schema.Properties {
		if err := resolveAllOfRefs(&v, contextPkg, p, pkgByPath); err != nil {
			return err
		}
		schema.Properties[k] = v
	}
	if schema.Items != nil && schema.Items.Schema != nil {
		if err := resolveAllOfRefs(schema.Items.Schema, contextPkg, p, pkgByPath); err != nil {
			return err
		}
	}
	if schema.AdditionalProperties != nil && schema.AdditionalProperties.Schema != nil {
		if err := resolveAllOfRefs(schema.AdditionalProperties.Schema, contextPkg, p, pkgByPath); err != nil {
			return err
		}
	}
	return nil
}

// convertRefs walks the schema and converts internal $ref links from the
// controller-tools format (#/definitions/pkg~1path~0TypeName) to swagger
// definition keys (#/definitions/io.k8s.pkg.path.TypeName).
func convertRefs(schema *apiextensionsv1.JSONSchemaProps, contextPkg *loader.Package) {
	if schema == nil {
		return
	}

	if schema.Ref != nil && len(*schema.Ref) > 0 {
		typeName, pkgPath, err := crd.RefParts(*schema.Ref)
		if err == nil {
			if pkgPath == "" && contextPkg != nil {
				pkgPath = contextPkg.PkgPath
			}
			newRef := "#/definitions/" + util.ToRESTFriendlyName(pkgPath+"."+typeName)
			schema.Ref = &newRef
		}
	}

	for k, v := range schema.Properties {
		convertRefs(&v, contextPkg)
		schema.Properties[k] = v
	}
	for i := range schema.AllOf {
		convertRefs(&schema.AllOf[i], contextPkg)
	}
	if schema.Items != nil && schema.Items.Schema != nil {
		convertRefs(schema.Items.Schema, contextPkg)
	}
	if schema.AdditionalProperties != nil && schema.AdditionalProperties.Schema != nil {
		convertRefs(schema.AdditionalProperties.Schema, contextPkg)
	}
}

// resolveRefDefinitions resolves top-level swagger definitions that are just a
// $ref to another definition. Such definitions arise from Go type definitions
// like `type Foo Bar` where the schema for Foo is a $ref to Bar.
// structured-merge-diff does not create separate named types for pure $ref
// definitions, so we resolve them by copying the target definition's schema and
// preserving any additional extensions (like x-kubernetes-map-type).
func resolveRefDefinitions(definitions map[string]any) {
	const refPrefix = "#/definitions/"
	for key, def := range definitions {
		defMap, ok := def.(map[string]any)
		if !ok {
			continue
		}
		ref, hasRef := defMap["$ref"].(string)
		if !hasRef {
			continue
		}
		// Resolve the $ref to the target definition.
		targetKey := strings.TrimPrefix(ref, refPrefix)
		targetDef, found := definitions[targetKey]
		if !found {
			continue
		}
		targetMap, ok := targetDef.(map[string]any)
		if !ok {
			continue
		}

		// Copy the target definition and merge any extra extensions
		// (e.g., x-kubernetes-map-type) from the original.
		resolved := make(map[string]any, len(targetMap)+len(defMap))
		maps.Copy(resolved, targetMap)
		for k, v := range defMap {
			if k == "$ref" {
				continue
			}
			resolved[k] = v
		}
		definitions[key] = resolved
	}
}

// sanitizeForOpenAPIV2 recursively removes OpenAPI v3-only constructs from a
// JSON schema map to make it valid OpenAPI v2 / Swagger 2.0. Fields removed
// include nullable, anyOf, oneOf, and not. The x-kubernetes-* extensions are
// preserved as they are handled by kube-openapi.
func sanitizeForOpenAPIV2(schema map[string]any) {
	// In swagger 2.0, a $ref is a standalone reference — no other properties
	// are allowed alongside it. The schema generator sometimes includes
	// type/format with refs for internal use; strip them here.
	if _, hasRef := schema["$ref"]; hasRef {
		delete(schema, "type")
		delete(schema, "format")
	}

	delete(schema, "nullable")
	delete(schema, "anyOf")
	delete(schema, "oneOf")
	delete(schema, "not")

	if props, ok := schema["properties"].(map[string]any); ok {
		for _, v := range props {
			if propSchema, ok := v.(map[string]any); ok {
				sanitizeForOpenAPIV2(propSchema)
			}
		}
	}

	if items, ok := schema["items"].(map[string]any); ok {
		sanitizeForOpenAPIV2(items)
	}

	if addProps, ok := schema["additionalProperties"].(map[string]any); ok {
		sanitizeForOpenAPIV2(addProps)
	}

	if allOf, ok := schema["allOf"].([]any); ok {
		for _, v := range allOf {
			if subSchema, ok := v.(map[string]any); ok {
				sanitizeForOpenAPIV2(subSchema)
			}
		}
	}
}
