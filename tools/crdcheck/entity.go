// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/cilium/cilium/pkg/policy/api"
)

// entityAPIPackage is the import path of the package that declares the Entity
// type and its +kubebuilder:validation:Enum marker.
const entityAPIPackage = "github.com/cilium/cilium/pkg/policy/api"

// entitiesFromCode returns the set of entity names that are the source of truth
// for the CRD Entity enum: every runtime-resolvable entity in
// api.EntitySelectorMapping, minus the internal-only ones in entitiesNotInCRD.
func entitiesFromCode() map[string]struct{} {
	want := make(map[string]struct{})
	for e := range api.EntitySelectorMapping {
		if _, internal := entitiesNotInCRD[e]; internal {
			continue
		}
		want[string(e)] = struct{}{}
	}
	return want
}

// entityEnumCRDs are the CRDs whose schema carries the Entity enum
// (via the toEntities/fromEntities policy fields).
var entityEnumCRDs = []string{
	"ciliumnetworkpolicies.cilium.io",
	"ciliumclusterwidenetworkpolicies.cilium.io",
}

// entitiesNotInCRD lists entities that exist as internal aggregation targets
// but are intentionally NOT user-facing policy values, so they are excluded
// from the CRD Entity enum. Removing an entry here without also adding it to
// the enum makes checkEntityEnum fail, that is deliberate: the exclusion is a
// documented decision, not silent drift.
var entitiesNotInCRD = map[api.Entity]struct{}{
	api.EntityWorldIPv4: {}, // internal-only: IPv4 split of `world`, not selectable in policy
	api.EntityWorldIPv6: {}, // internal-only: IPv6 split of `world`, not selectable in policy
}

// checkEntityEnum verifies that the Entity enum in the network policy CRDs
// stays in sync with the entities the policy engine can actually resolve
// (api.EntitySelectorMapping). It catches adding, modifying or removing an
// entity in Go without updating the +kubebuilder:validation:Enum marker in
// pkg/policy/api/entity.go from api.Entity (and vice-versa), at `make manifests` time rather
// than at runtime.
func checkEntityEnum(crd *crdv1.CustomResourceDefinition) error {
	if !slices.Contains(entityEnumCRDs, crd.GetName()) {
		return nil
	}

	// source of truth: every runtime-resolvable entity minus internal-only ones.
	want := entitiesFromCode()

	// collect every Entity enum occurrence in the CRD schema. toEntities and
	// fromEntities appear in several places, including under `specs`.
	got := make(map[string]struct{})
	for _, v := range crd.Spec.Versions {
		if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
			continue
		}
		collectEntityEnums(v.Schema.OpenAPIV3Schema, got)
	}
	if len(got) == 0 {
		return fmt.Errorf("%s: no Entity enum found in schema; did the toEntities/fromEntities fields change", crd.GetName())
	}

	var missingInCRD, unexpectedInCRD []string
	for e := range want {
		if _, ok := got[e]; !ok {
			missingInCRD = append(missingInCRD, e)
		}
	}
	for e := range got {
		if _, ok := want[e]; !ok {
			unexpectedInCRD = append(unexpectedInCRD, e)
		}
	}
	var errs []error
	if len(missingInCRD) > 0 {
		slices.Sort(missingInCRD)
		errs = append(errs, fmt.Errorf("Entity enum in %s is missing entities that are supported in code: %v\n"+
			"add them to the +kubebuilder:validation:Enum marker in pkg/policy/api/entity.go and run `make manifests`,"+
			"or add them to entitiesNotInCRD in tools/crdcheck/entity.go if they are internal-only",
			crd.GetName(), missingInCRD))
	}
	if len(unexpectedInCRD) > 0 {
		slices.Sort(unexpectedInCRD)
		errs = append(errs, fmt.Errorf("Entity enum in %s contains entities that are not supported in code: %v\n"+
			"remove them from the +kubebuilder:validation:Enum marker in pkg/policy/api/entity.go and run `make manifests`,"+
			"or add them to api.EntitySelectorMapping if they should be supported",
			crd.GetName(), unexpectedInCRD))
	}

	return errors.Join(errs...)
}

// checkEntityEnumMarker verifies that the +kubebuilder:validation:Enum marker
// on the api.Entity type is itself in sync with api.EntitySelectorMapping. This
// complements checkEntityEnum (which checks the generated CRD): it catches a
// stale marker directly in the Go source, before generation, so a wrong marker
// cannot silently produce a wrong-but-self-consistent CRD.
func checkEntityEnumMarker() error {
	markerVals, err := entityEnumMarkerValues()
	if err != nil {
		return err
	}

	want := entitiesFromCode()

	var missingInMarker, unexpectedInMarker []string
	for e := range want {
		if _, ok := markerVals[e]; !ok {
			missingInMarker = append(missingInMarker, e)
		}
	}
	for e := range markerVals {
		if _, ok := want[e]; !ok {
			unexpectedInMarker = append(unexpectedInMarker, e)
		}
	}

	var errs []error
	if len(missingInMarker) > 0 {
		slices.Sort(missingInMarker)
		errs = append(errs, fmt.Errorf("the +kubebuilder:validation:Enum marker on api.Entity is missing entities that are supported in code: %v\n"+
			"add them to the marker in pkg/policy/api/entity.go, "+
			"or add them to entitiesNotInCRD in tools/crdcheck/entity.go if they are internal-only",
			missingInMarker))
	}
	if len(unexpectedInMarker) > 0 {
		slices.Sort(unexpectedInMarker)
		errs = append(errs, fmt.Errorf("the +kubebuilder:validation:Enum marker on api.Entity contains entities that are not supported in code: %v\n"+
			"remove them from the marker in pkg/policy/api/entity.go, "+
			"or add them to api.EntitySelectorMapping if they should be supported",
			unexpectedInMarker))
	}

	return errors.Join(errs...)
}

// entityEnumMarkerValues loads the api package source and extracts the values
// of the +kubebuilder:validation:Enum marker attached to the Entity type.
func entityEnumMarkerValues() (map[string]struct{}, error) {
	const marker = "+kubebuilder:validation:Enum="

	cfg := &packages.Config{Mode: packages.NeedSyntax | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, entityAPIPackage)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", entityAPIPackage, err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("errors loading %s", entityAPIPackage)
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Doc == nil {
					continue
				}
				// Ensure this declaration defines the Entity type.
				if !declaresType(gd, "Entity") {
					continue
				}
				for _, c := range gd.Doc.List {
					line := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
					if !strings.HasPrefix(line, marker) {
						continue
					}
					out := make(map[string]struct{})
					for _, v := range strings.Split(strings.TrimPrefix(line, marker), ";") {
						if v = strings.TrimSpace(v); v != "" {
							out[v] = struct{}{}
						}
					}
					return out, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find +kubebuilder:validation:Enum marker on api.Entity in %s", entityAPIPackage)
}

// declaresType reports whether the type declaration defines a type with the
// given name.
func declaresType(gd *ast.GenDecl, name string) bool {
	for _, spec := range gd.Specs {
		if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.Name == name {
			return true
		}
	}
	return false
}

// collectEntityEnums walks the schema and records the enum values of any
// toEntities/fromEntities array property it finds.
func collectEntityEnums(s *crdv1.JSONSchemaProps, out map[string]struct{}) {
	if s == nil {
		return
	}
	for name, prop := range s.Properties {
		if (name == "toEntities" || name == "fromEntities") && prop.Items != nil && prop.Items.Schema != nil {
			for _, ev := range prop.Items.Schema.Enum {
				var v string
				if err := json.Unmarshal(ev.Raw, &v); err == nil {
					out[v] = struct{}{}
				}
			}
		}
		collectEntityEnums(&prop, out)
	}
	if s.Items != nil && s.Items.Schema != nil {
		collectEntityEnums(s.Items.Schema, out)
	}
}
