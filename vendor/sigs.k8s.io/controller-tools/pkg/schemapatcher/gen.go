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

package schemapatcher

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v3"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kyaml "sigs.k8s.io/yaml"

	crdgen "sigs.k8s.io/controller-tools/pkg/crd"
	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
	yamlop "sigs.k8s.io/controller-tools/pkg/schemapatcher/internal/yaml"
)

// NB(directxman12): this code is quite fragile, but there are a sufficient
// number of corner cases that it's hard to decompose into separate tools.
// When in doubt, ping @sttts.
//
// Namely:
// - It needs to only update existing versions
// - It needs to make "stable" changes that don't mess with map key ordering
//   (in order to facilitate validating that no change has occurred)
// - It needs to collapse identical schema versions into a top-level schema,
//   if all versions are identical (this is a common requirement to all CRDs,
//   but in this case it means simple jsonpatch wouldn't suffice)

// TODO(directxman12): When CRD v1 rolls around, consider splitting this into a
// tool that generates a patch, and a separate tool for applying stable YAML
// patches.

var (
	currentAPIExtVersion = apiext.SchemeGroupVersion.String()
)

// +controllertools:marker:generateHelp

// Generator patches existing CRDs with new schemata.
//
// It will generate output for each "CRD Version" (API version of the CRD type
// itself) , e.g. apiextensions/v1) available.
type Generator struct {
	// ManifestsPath contains the CustomResourceDefinition YAML files.
	ManifestsPath string `marker:"manifests"`

	// MaxDescLen specifies the maximum description length for fields in CRD's OpenAPI schema.
	//
	// 0 indicates drop the description for all fields completely.
	// n indicates limit the description to at most n characters and truncate the description to
	// closest sentence boundary if it exceeds n characters.
	MaxDescLen *int `marker:",optional"`

	// GenerateEmbeddedObjectMeta specifies if any embedded ObjectMeta in the CRD should be generated
	GenerateEmbeddedObjectMeta *bool `marker:",optional"`
}

var _ genall.Generator = &Generator{}

func (Generator) CheckFilter() loader.NodeFilter {
	return crdgen.Generator{}.CheckFilter()
}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	return crdmarkers.Register(into)
}

func (g Generator) Generate(ctx *genall.GenerationContext) (result error) {
	parser := &crdgen.Parser{
		Collector: ctx.Collector,
		Checker:   ctx.Checker,
		// Indicates the parser on whether to register the ObjectMeta type or not
		GenerateEmbeddedObjectMeta: g.GenerateEmbeddedObjectMeta != nil && *g.GenerateEmbeddedObjectMeta == true,
	}

	crdgen.AddKnownTypes(parser)
	for _, root := range ctx.Roots {
		parser.NeedPackage(root)
	}

	metav1Pkg := crdgen.FindMetav1(ctx.Roots)
	if metav1Pkg == nil {
		// no objects in the roots, since nothing imported metav1
		return nil
	}

	// load existing CRD manifests with group-kind and versions
	partialCRDSets, err := crdsFromDirectory(ctx, g.ManifestsPath)
	if err != nil {
		return err
	}

	// generate schemata for the types we care about, and save them to be written later.
	for groupKind := range crdgen.FindKubeKinds(parser, metav1Pkg) {
		existingSet, wanted := partialCRDSets[groupKind]
		if !wanted {
			continue
		}

		for pkg, gv := range parser.GroupVersions {
			if gv.Group != groupKind.Group {
				continue
			}
			if _, wantedVersion := existingSet.Versions[gv.Version]; !wantedVersion {
				continue
			}

			typeIdent := crdgen.TypeIdent{Package: pkg, Name: groupKind.Kind}
			parser.NeedFlattenedSchemaFor(typeIdent)

			fullSchema := parser.FlattenedSchemata[typeIdent]
			if g.MaxDescLen != nil {
				fullSchema = *fullSchema.DeepCopy()
				crdgen.TruncateDescription(&fullSchema, *g.MaxDescLen)
			}

			// Fix top level ObjectMeta regardless of the settings.
			if _, ok := fullSchema.Properties["metadata"]; ok {
				fullSchema.Properties["metadata"] = apiext.JSONSchemaProps{Type: "object"}
			}

			existingSet.NewSchemata[gv.Version] = fullSchema
		}
	}

	// patch existing CRDs with new schemata
	for _, existingSet := range partialCRDSets {
		// first, figure out if we need to merge schemata together if they're *all*
		// identical (meaning we also don't have any "unset" versions)

		if len(existingSet.NewSchemata) == 0 {
			continue
		}

		// copy over the new versions that we have, keeping old versions so
		// that we can tell if a schema would be nil
		var someVer string
		for ver := range existingSet.NewSchemata {
			someVer = ver
			existingSet.Versions[ver] = struct{}{}
		}

		allSame := true
		firstSchema := existingSet.NewSchemata[someVer]
		for ver := range existingSet.Versions {
			otherSchema, hasSchema := existingSet.NewSchemata[ver]
			if !hasSchema || !equality.Semantic.DeepEqual(firstSchema, otherSchema) {
				allSame = false
				break
			}
		}

		if allSame {
			if err := existingSet.setGlobalSchema(); err != nil {
				return fmt.Errorf("failed to set global firstSchema for %s: %w", existingSet.GroupKind, err)
			}
		} else {
			if err := existingSet.setVersionedSchemata(); err != nil {
				return fmt.Errorf("failed to set versioned schemas for %s: %w", existingSet.GroupKind, err)
			}
		}
	}

	// write the final result out to the new location
	for _, set := range partialCRDSets {
		// We assume all CRD versions came from different files, since this
		// is how controller-gen works.  If they came from the same file,
		// it'd be non-sensical, since you couldn't reasonably use kubectl
		// with them against older servers.
		for _, crd := range set.CRDVersions {
			if err := func() error {
				outWriter, err := ctx.OutputRule.Open(nil, crd.FileName)
				if err != nil {
					return err
				}
				defer outWriter.Close()

				enc := yaml.NewEncoder(outWriter)
				// yaml.v2 defaults to indent=2, yaml.v3 defaults to indent=4,
				// so be compatible with everything else in k8s and choose 2.
				enc.SetIndent(2)

				return enc.Encode(crd.Yaml)
			}(); err != nil {
				return err
			}
		}
	}

	return nil
}

// partialCRDSet represents a set of CRDs of different apiext versions
// (v1beta1.CRD vs v1.CRD) that represent the same GroupKind.
//
// It tracks modifications to the schemata of those CRDs from this source file,
// plus some useful structured content, and keeps track of the raw YAML representation
// of the different apiext versions.
type partialCRDSet struct {
	// GroupKind is the GroupKind represented by this CRD.
	GroupKind schema.GroupKind
	// NewSchemata are the new schemata generated from Go IDL by controller-gen.
	NewSchemata map[string]apiext.JSONSchemaProps
	// CRDVersions are the forms of this CRD across different apiextensions
	// versions
	CRDVersions []*partialCRD
	// Versions are the versions of the given GroupKind in this set of CRDs.
	Versions map[string]struct{}
}

// partialCRD represents the raw YAML encoding of a given CRD instance, plus
// the versions contained therein for easy lookup.
type partialCRD struct {
	// Yaml is the raw YAML structure of the CRD.
	Yaml *yaml.Node
	// FileName is the source name of the file that this was read from.
	//
	// This isn't on partialCRDSet because we could have different CRD versions
	// stored in the same file (like controller-tools does by default) or in
	// different files.
	FileName string

	// CRDVersion is the version of the CRD object itself, from
	// apiextensions (currently apiextensions/v1 or apiextensions/v1beta1).
	CRDVersion string
}

// setGlobalSchema sets the versioned schemas (as per setVersionedSchemata).
func (e *partialCRDSet) setGlobalSchema() error {
	for _, crdInfo := range e.CRDVersions {
		if err := crdInfo.setVersionedSchemata(e.NewSchemata); err != nil {
			return err
		}
	}
	return nil
}

// getVersionsNode gets the YAML node of .spec.versions YAML mapping,
// if returning the node, and whether or not it was present.
func (e *partialCRD) getVersionsNode() (*yaml.Node, bool, error) {
	versions, found, err := yamlop.GetNode(e.Yaml, "spec", "versions")
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	if versions.Kind != yaml.SequenceNode {
		return nil, true, fmt.Errorf("unexpected non-sequence versions")
	}
	return versions, found, nil
}

// setVersionedSchemata sets the versioned schemata on each encoding in this set as per
// setVersionedSchemata on partialCRD.
func (e *partialCRDSet) setVersionedSchemata() error {
	for _, crdInfo := range e.CRDVersions {
		if err := crdInfo.setVersionedSchemata(e.NewSchemata); err != nil {
			return err
		}
	}
	return nil
}

// setVersionedSchemata populates all existing versions with new schemata,
// wiping the schema of any version that doesn't have a listed schema.
// Any "unknown" versions are ignored.
func (e *partialCRD) setVersionedSchemata(newSchemata map[string]apiext.JSONSchemaProps) error {
	var err error
	if err := yamlop.DeleteNode(e.Yaml, "spec", "validation"); err != nil {
		return err
	}

	versions, found, err := e.getVersionsNode()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("unexpected missing versions")
	}

	for i, verNode := range versions.Content {
		nameNode, _, _ := yamlop.GetNode(verNode, "name")
		if nameNode.Kind != yaml.ScalarNode || nameNode.ShortTag() != "!!str" {
			return fmt.Errorf("version name was not a string at spec.versions[%d]", i)
		}
		name := nameNode.Value
		if name == "" {
			return fmt.Errorf("unexpected empty name at spec.versions[%d]", i)
		}
		newSchema, found := newSchemata[name]
		if !found {
			if err := yamlop.DeleteNode(verNode, "schema"); err != nil {
				return fmt.Errorf("spec.versions[%d]: %w", i, err)
			}
		} else {
			schemaNodeTree, err := yamlop.ToYAML(newSchema)
			if err != nil {
				return fmt.Errorf("failed to convert schema to YAML: %w", err)
			}
			schemaNodeTree = schemaNodeTree.Content[0] // get rid of the document node
			yamlop.SetStyle(schemaNodeTree, 0)         // clear the style so it defaults to an auto-chosen one
			if err := yamlop.SetNode(verNode, *schemaNodeTree, "schema", "openAPIV3Schema"); err != nil {
				return fmt.Errorf("spec.versions[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// crdsFromDirectory returns loads all CRDs from the given directory in a
// manner that preserves ordering, comments, etc in order to make patching
// minimally invasive.  Returned CRDs are mapped by group-kind.
func crdsFromDirectory(ctx *genall.GenerationContext, dir string) (map[schema.GroupKind]*partialCRDSet, error) {
	res := map[schema.GroupKind]*partialCRDSet{}
	dirEntries, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, fileInfo := range dirEntries {
		// find all files that are YAML
		if fileInfo.IsDir() || filepath.Ext(fileInfo.Name()) != ".yaml" {
			continue
		}

		rawContent, err := ctx.ReadFile(filepath.Join(dir, fileInfo.Name()))
		if err != nil {
			return nil, err
		}

		// NB(directxman12): we could use the universal deserializer for this, but it's
		// really pretty clunky, and the alternative is actually kinda easier to understand

		// ensure that this is a CRD
		var typeMeta metav1.TypeMeta
		if err := kyaml.Unmarshal(rawContent, &typeMeta); err != nil {
			continue
		}
		if !isSupportedAPIExtGroupVer(typeMeta.APIVersion) {
			return nil, fmt.Errorf("load %q: apiVersion %q not supported", filepath.Join(dir, fileInfo.Name()), typeMeta.APIVersion)
		}
		if typeMeta.Kind != "CustomResourceDefinition" {
			continue
		}

		// collect the group-kind and versions from the actual structured form
		var actualCRD crdIsh
		if err := kyaml.Unmarshal(rawContent, &actualCRD); err != nil {
			continue
		}
		groupKind := schema.GroupKind{Group: actualCRD.Spec.Group, Kind: actualCRD.Spec.Names.Kind}
		versions := make(map[string]struct{}, len(actualCRD.Spec.Versions))
		for _, ver := range actualCRD.Spec.Versions {
			versions[ver.Name] = struct{}{}
		}

		// then actually unmarshal in a manner that preserves ordering, etc
		var yamlNodeTree yaml.Node
		if err := yaml.Unmarshal(rawContent, &yamlNodeTree); err != nil {
			continue
		}

		// then store this CRDVersion of the CRD in a set, populating the set if necessary
		if res[groupKind] == nil {
			res[groupKind] = &partialCRDSet{
				GroupKind:   groupKind,
				NewSchemata: make(map[string]apiext.JSONSchemaProps),
				Versions:    make(map[string]struct{}),
			}
		}
		for ver := range versions {
			res[groupKind].Versions[ver] = struct{}{}
		}
		res[groupKind].CRDVersions = append(res[groupKind].CRDVersions, &partialCRD{
			Yaml:       &yamlNodeTree,
			FileName:   fileInfo.Name(),
			CRDVersion: typeMeta.APIVersion,
		})
	}
	return res, nil
}

// isSupportedAPIExtGroupVer checks if the given string-form group-version
// is one of the known apiextensions versions (v1).
func isSupportedAPIExtGroupVer(groupVer string) bool {
	return groupVer == currentAPIExtVersion
}

// crdIsh is a merged blob of CRD fields that looks enough like all versions of
// CRD to extract the relevant information for partialCRDSet and partialCRD.
//
// We keep this separate so it's clear what info we need, and so we don't break
// when we switch canonical internal versions and lose old fields while gaining
// new ones (like in v1beta1 --> v1).
//
// Its use is tied directly to crdsFromDirectory, and is mostly an implementation detail of that.
type crdIsh struct {
	Spec struct {
		Group string `json:"group"`
		Names struct {
			Kind string `json:"kind"`
		} `json:"names"`
		Versions []struct {
			Name string `json:"name"`
		} `json:"versions"`
	} `json:"spec"`
}
