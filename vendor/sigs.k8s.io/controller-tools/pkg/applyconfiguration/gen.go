/*
Copyright 2021 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/gengo/v2/types"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/code-generator/cmd/applyconfiguration-gen/args"
	"k8s.io/code-generator/cmd/applyconfiguration-gen/generators"

	"k8s.io/gengo/v2"
	"k8s.io/gengo/v2/generator"
	"k8s.io/gengo/v2/parser"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	crdmarkers "sigs.k8s.io/controller-tools/pkg/crd/markers"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/internal/crd"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// Based on deepcopy gen but with legacy marker support removed.

var (
	isCRDMarker      = markers.Must(markers.MakeDefinition("kubebuilder:resource", markers.DescribesType, crdmarkers.Resource{}))
	enablePkgMarker  = markers.Must(markers.MakeDefinition("kubebuilder:ac:generate", markers.DescribesPackage, false))
	outputPkgMarker  = markers.Must(markers.MakeDefinition("kubebuilder:ac:output:package", markers.DescribesPackage, ""))
	enableTypeMarker = markers.Must(markers.MakeDefinition("kubebuilder:ac:generate", markers.DescribesType, false))
)

const defaultOutputPackage = "applyconfiguration"

// +controllertools:marker:generateHelp

// Generator generates code containing apply configuration type implementations.
type Generator struct {
	// HeaderFile specifies the header text (e.g. license) to prepend to generated files.
	HeaderFile string `marker:",optional"`

	// ExternalApplyConfigurations provides mappings between external types and their applyconfiguration packages.
	//
	// Use this to reference apply configuration types for external types referenced
	// by the Go structs provided as input. Each entry should be in the format:
	//   <package>.<TypeName>@<applyconfiguration-package>
	//
	// For example, to reference the apply configuration for corev1.LocalObjectReference:
	//   k8s.io/api/core/v1.LocalObjectReference@k8s.io/client-go/applyconfigurations/core/v1
	ExternalApplyConfigurations []string `marker:",optional"`
}

func (Generator) CheckFilter() loader.NodeFilter {
	return func(node ast.Node) bool {
		// ignore interfaces
		_, isIface := node.(*ast.InterfaceType)
		return !isIface
	}
}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	if err := markers.RegisterAll(into,
		isCRDMarker, enablePkgMarker, enableTypeMarker, outputPkgMarker); err != nil {
		return err
	}

	if err := crdmarkers.Register(into); err != nil {
		return err
	}

	into.AddHelp(isCRDMarker,
		markers.SimpleHelp("apply", "enables apply configuration generation for this type"))
	into.AddHelp(
		enableTypeMarker, markers.SimpleHelp("apply", "overrides enabling or disabling applyconfiguration generation for the type, can be used to generate applyconfiguration for a single type when the package generation is disabled, or to disable generation for a single type when the package generation is enabled"))
	into.AddHelp(
		enablePkgMarker, markers.SimpleHelp("apply", "overrides enabling or disabling applyconfiguration generation for the package"))
	into.AddHelp(
		outputPkgMarker, markers.SimpleHelp("apply", "overrides the default output package for the applyconfiguration generation, supports relative paths to the API directory. The default value is \"applyconfiguration\""))
	return nil
}

func enabledOnPackage(col *markers.Collector, pkg *loader.Package) (bool, error) {
	pkgMarkers, err := markers.PackageMarkers(col, pkg)
	if err != nil {
		return false, err
	}
	pkgMarker := pkgMarkers.Get(enablePkgMarker.Name)
	if pkgMarker != nil {
		return pkgMarker.(bool), nil
	}
	return false, nil
}

func enabledOnType(info *markers.TypeInfo) bool {
	if typeMarker := info.Markers.Get(enableTypeMarker.Name); typeMarker != nil {
		return typeMarker.(bool)
	}
	return isCRD(info)
}

func outputPkg(col *markers.Collector, pkg *loader.Package) string {
	pkgMarkers, err := markers.PackageMarkers(col, pkg)
	if err != nil {
		// Use the default when there's an error.
		return defaultOutputPackage
	}

	pkgMarker := pkgMarkers.Get(outputPkgMarker.Name)
	if pkgMarker != nil {
		return pkgMarker.(string)
	}

	return defaultOutputPackage
}

func isCRD(info *markers.TypeInfo) bool {
	objectEnabled := info.Markers.Get(isCRDMarker.Name)
	return objectEnabled != nil
}

func (d Generator) Generate(ctx *genall.GenerationContext) error {
	headerFilePath := d.HeaderFile

	if headerFilePath == "" {
		tmpFile, err := os.CreateTemp("", "applyconfig-header-*.txt")
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close temporary file: %w", err)
		}

		defer os.Remove(tmpFile.Name())

		headerFilePath = tmpFile.Name()
	}

	// Parse external apply configurations
	externalACs := make(map[types.Name]string)
	for _, ext := range d.ExternalApplyConfigurations {
		parts := strings.SplitN(ext, "@", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid external apply configuration format %q, expected <package>.<TypeName>@<applyconfiguration-package>", ext)
		}
		typeName := types.ParseFullyQualifiedName(parts[0])
		externalACs[typeName] = parts[1]
	}

	objGenCtx := ObjectGenCtx{
		Collector:                   ctx.Collector,
		Checker:                     ctx.Checker,
		HeaderFilePath:              headerFilePath,
		ExternalApplyConfigurations: externalACs,
	}

	errs := []error{}
	for _, pkg := range ctx.Roots {
		if err := objGenCtx.generateForPackage(pkg); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return kerrors.NewAggregate(errs)
	}

	return nil
}

// ObjectGenCtx contains the common info for generating apply configuration implementations.
// It mostly exists so that generating for a package can be easily tested without
// requiring a full set of output rules, etc.
type ObjectGenCtx struct {
	Collector                   *markers.Collector
	Checker                     *loader.TypeChecker
	HeaderFilePath              string
	ExternalApplyConfigurations map[types.Name]string
}

// generateForPackage generates apply configuration implementations for
// types in the given package, writing the formatted result to given writer.
func (ctx *ObjectGenCtx) generateForPackage(root *loader.Package) error {
	enabled, _ := enabledOnPackage(ctx.Collector, root)
	if !enabled {
		return nil
	}
	if len(root.GoFiles) == 0 {
		return nil
	}

	arguments := args.New()
	arguments.GoHeaderFile = ctx.HeaderFilePath

	// Set external apply configurations
	maps.Copy(arguments.ExternalApplyConfigurations, ctx.ExternalApplyConfigurations)

	outpkg := outputPkg(ctx.Collector, root)

	arguments.OutputDir = filepath.Join(root.Dir, outpkg)
	arguments.OutputPkg = filepath.Join(root.Package.PkgPath, outpkg)

	// The following code is based on gengo/v2.Execute.
	// We have lifted it from there so that we can adjust the markers on the types to make sure
	// that Kubebuilder generation markers are converted into the genclient marker
	// prior to executing the targets.
	buildTags := []string{gengo.StdBuildTag}
	p := parser.NewWithOptions(parser.Options{BuildTags: buildTags})
	if err := p.LoadPackages(root.PkgPath); err != nil {
		return fmt.Errorf("failed making a parser: %w", err)
	}

	c, err := generator.NewContext(p, generators.NameSystems(), generators.DefaultNameSystem())
	if err != nil {
		return fmt.Errorf("failed making a context: %w", err)
	}

	pkg, ok := c.Universe[root.PkgPath]
	if !ok {
		return fmt.Errorf("package %q not found in universe", root.Name)
	}

	pkgMarkers, err := markers.PackageMarkers(ctx.Collector, root)
	if err != nil {
		return fmt.Errorf("failed to get package markers: %w", err)
	}

	gv := crd.GroupVersionForPackage(pkgMarkers, root)
	if gv.Empty() {
		return errors.New("could not infer groupVersion for package - Is the `// +groupName` marker set?")
	}

	pkg.Comments = append(pkg.Comments, "+groupName="+gv.Group)

	// For each type we think should be generated, make sure it has a genclient
	// marker else the apply generator will not generate it.
	if err := markers.EachType(ctx.Collector, root, func(info *markers.TypeInfo) {
		if !enabledOnType(info) {
			return
		}

		typ, ok := pkg.Types[info.Name]
		if !ok {
			return
		}

		comments := sets.NewString(typ.CommentLines...)
		comments.Insert(typ.SecondClosestCommentLines...)

		if !comments.Has("// +genclient") {
			typ.CommentLines = append(typ.CommentLines, "+genclient")
		}

		// Check if the resource is cluster-scoped
		if isCRDClusterScoped(info) && !comments.Has("// +genclient:nonNamespaced") {
			typ.CommentLines = append(typ.CommentLines, "+genclient:nonNamespaced")
		}
	}); err != nil {
		return err
	}

	schemaFile, err := ctx.buildOpenAPISchema(root, gv)
	if err != nil {
		return fmt.Errorf("failed to build OpenAPI schema: %w", err)
	}
	if schemaFile != "" {
		defer os.Remove(schemaFile)
		arguments.OpenAPISchemaFilePath = schemaFile
	}

	targets := generators.GetTargets(c, arguments)
	if err := c.ExecuteTargets(targets); err != nil {
		return fmt.Errorf("failed executing generator: %w", err)
	}

	return nil
}

func isCRDClusterScoped(info *markers.TypeInfo) bool {
	resourceMarker := info.Markers.Get(isCRDMarker.Name)
	if resourceMarker == nil {
		return false
	}
	resource, ok := resourceMarker.(crdmarkers.Resource)
	if !ok {
		return false
	}
	return resource.Scope == string(apiextensionsv1.ClusterScoped)
}
