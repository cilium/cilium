// Copyright 2019 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package licenses

import (
	"context"
	"fmt"
	"go/build"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-licenses/internal/third_party/pkgsite/source"
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/packages"
	"k8s.io/klog/v2"
)

// Library is a collection of packages covered by the same license file.
type Library struct {
	// LicenseFile is the path of the file containing the library's license.
	LicenseFile string
	// Packages contains import paths for Go packages in this library.
	// It may not be the complete set of all packages in the library.
	Packages []string
	// Parent go module.
	module *Module
	// List of licenses for found at the LicenseFile.
	Licenses []License
}

// PackagesError aggregates all Packages[].Errors into a single error.
type PackagesError struct {
	pkgs []*packages.Package
}

func (e PackagesError) Error() string {
	var str strings.Builder
	str.WriteString(fmt.Sprintf("errors for %q:", e.pkgs))
	packages.Visit(e.pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			str.WriteString(fmt.Sprintf("\n%s: %s", pkg.PkgPath, err))
		}
	})
	return str.String()
}

// Libraries returns the collection of libraries used by this package, directly or transitively.
// A library is a collection of one or more packages covered by the same license file.
// Packages not covered by a license will be returned as individual libraries.
// Standard library packages will be ignored.
func Libraries(ctx context.Context, classifier Classifier, includeTests bool, ignoredPaths []string, importPaths ...string) ([]*Library, error) {
	// These are the steps we take to find libraries:
	// 1. we list all modules and all packages
	// 2. for each package, we find a list of candidates
	// 3. we deduplicate all candidates
	// 4. for each candidate, we classify if the candidate is a license file
	// 5. for each package, we select the first candidates that is a license
	//    file & add the package to a list of packages for that license file
	// 6. we return an array of libraries (which are the license files, the
	//    found licenses in that file, all the packages that had that file as
	//    its first candidate and the module in which those packages live)

	cfg := &packages.Config{
		Context: ctx,
		Mode:    packages.NeedImports | packages.NeedDeps | packages.NeedFiles | packages.NeedName | packages.NeedModule,
		Tests:   includeTests,
	}

	rootPkgs, err := packages.Load(cfg, importPaths...)
	if err != nil {
		return nil, err
	}

	vendoredSearch := []*Module{}
	for _, parentPkg := range rootPkgs {
		if parentPkg.Module == nil {
			continue
		}

		module := newModule(parentPkg.Module)
		if module.Dir == "" {
			continue
		}

		vendoredSearch = append(vendoredSearch, module)
	}

	type pkgInfo struct {
		// pkgPath is the import path of the package.
		pkgPath string
		// modulePath is the module path of the package.
		modulePath string

		// pkgDir is the directory containing the package's source code.
		pkgDir string
		// moduleDir is the directory containing the module's source code.
		moduleDir string
	}

	allModules := map[string]*Module{}
	allPackages := []pkgInfo{}
	{
		pkgErrorOccurred := false
		otherErrorOccurred := false
		packages.Visit(rootPkgs, func(p *packages.Package) bool {
			if len(p.Errors) > 0 {
				pkgErrorOccurred = true
				return false
			}
			if isStdLib(p) {
				// No license requirements for the Go standard library.
				return false
			}
			if includeTests && isTestBinary(p) {
				// A test binary only imports the standard library, so we do not need to check its license.
				// Moreover, Find below will return an error because pkgDir is not under p.Module.Dir
				// as pkgDir is under GOCACHE instead.
				return false
			}
			for _, i := range ignoredPaths {
				if strings.HasPrefix(p.PkgPath, i) {
					// Marked to be ignored.
					return true
				}
			}

			if len(p.OtherFiles) > 0 {
				klog.Warningf("%q contains non-Go code that can't be inspected for further dependencies:\n%s", p.PkgPath, strings.Join(p.OtherFiles, "\n"))
			}

			var pkgDir string
			switch {
			case len(p.GoFiles) > 0:
				pkgDir = filepath.Dir(p.GoFiles[0])
			case len(p.CompiledGoFiles) > 0:
				pkgDir = filepath.Dir(p.CompiledGoFiles[0])
			case len(p.OtherFiles) > 0:
				pkgDir = filepath.Dir(p.OtherFiles[0])
			default:
				// This package is empty - nothing to do.
				return true
			}

			if p.Module == nil {
				otherErrorOccurred = true
				klog.Errorf("Package %s does not have module info. Non go modules projects are no longer supported. For feedback, refer to https://github.com/google/go-licenses/issues/128.", p.PkgPath)
				return false
			}

			module := newModule(p.Module)

			if module.Dir == "" {
				// A known cause is that the module is vendored, so some information is lost.
				isVendored := strings.Contains(pkgDir, "/vendor/")
				if !isVendored {
					klog.Warningf("module %s does not have dir and it's not vendored, cannot discover the license URL. Report to go-licenses developer if you see this.", module.Path)
				} else {
					// This is vendored. Handle this known special case.

					// Extra note why we identify a vendored package like this.
					//
					// For a normal package:
					// * if it's not in a module, lib.module == nil
					// * if it's in a module, lib.module.Dir != ""
					// Only vendored modules will have lib.module != nil && lib.module.Path != "" && lib.module.Dir == "" as far as I know.
					// So the if condition above is already very strict for vendored packages.
					// On top of it, we checked the lib.LicensePath contains a vendor folder in it.
					// So it's rare to have a false positive for both conditions at the same time, although it may happen in theory.
					//
					// These assumptions may change in the future,
					// so we need to keep this updated with go tooling changes.
					for _, parentModule := range vendoredSearch {
						if strings.HasPrefix(pkgDir, parentModule.Dir) {
							module = parentModule
							break
						}
					}

					if module.Dir == "" {
						klog.Warningf("cannot find parent package of vendored module %s", module.Path)
					}
				}
			}

			allPackages = append(allPackages, pkgInfo{
				pkgPath:    p.PkgPath,
				modulePath: module.Path,
				pkgDir:     pkgDir,
				moduleDir:  module.Dir,
			})
			allModules[module.Path] = module

			return true
		}, nil)
		if pkgErrorOccurred {
			return nil, PackagesError{
				pkgs: rootPkgs,
			}
		}
		if otherErrorOccurred {
			return nil, fmt.Errorf("some errors occurred when loading direct and transitive dependency packages")
		}
	}

	pkgCandidates := map[string][]string{}
	allCandidates := map[string]struct{}{}
	for _, pkg := range allPackages {
		candidates, err := FindCandidates(pkg.pkgDir, pkg.moduleDir)
		if err != nil {
			return nil, err
		}

		pkgCandidates[pkg.pkgDir] = candidates
		for _, candidate := range candidates {
			allCandidates[candidate] = struct{}{}
		}
	}

	group, _ := errgroup.WithContext(ctx)
	foundLicenseSlice := make([]struct {
		candidate string
		licenes   []License
	}, len(allCandidates))
	counter := 0
	for candidate := range allCandidates {
		idx := counter
		counter++
		candidate := candidate

		group.Go(func() error {
			licenses, err := classifier.Identify(candidate)
			if err != nil {
				klog.Errorf("Failed to parse %s: %v", candidate, err)
				return nil // Continue even if one LICENSE file fails to parse.
			}

			foundLicenseSlice[idx] = struct {
				candidate string
				licenes   []License
			}{
				candidate: candidate,
				licenes:   licenses,
			}
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	foundLicenses := map[string][]License{}
	for _, found := range foundLicenseSlice {
		if len(found.licenes) == 0 {
			continue
		}

		foundLicenses[found.candidate] = found.licenes
	}

	pkgsByLicense := make(map[string][]pkgInfo)
	for _, pkg := range allPackages {
		candidates := pkgCandidates[pkg.pkgDir]

		bestCandidate := ""
		for _, candidate := range candidates {
			if _, ok := foundLicenses[candidate]; ok {
				bestCandidate = candidate
				break
			}
		}

		pkgsByLicense[bestCandidate] = append(pkgsByLicense[bestCandidate], pkg)
	}

	var libraries []*Library
	for licenseFile, pkgs := range pkgsByLicense {
		if licenseFile == "" {
			// No license for these packages - return each one as a separate library.
			for _, p := range pkgs {
				libraries = append(libraries, &Library{
					Packages: []string{p.pkgPath},
					module:   allModules[p.modulePath],
				})
			}
			continue
		}

		lib := &Library{
			LicenseFile: licenseFile,
			Licenses:    foundLicenses[licenseFile],
			Packages:    make([]string, len(pkgs)),
			module:      allModules[pkgs[0].modulePath],
		}

		for i, p := range pkgs {
			lib.Packages[i] = p.pkgPath
		}

		libraries = append(libraries, lib)
	}

	// Sort libraries to produce a stable result for snapshot diffing.
	sort.Slice(libraries, func(i, j int) bool {
		return libraries[i].Name() < libraries[j].Name()
	})

	return libraries, nil
}

// Name is the common prefix of the import paths for all of the packages in this library.
func (l *Library) Name() string {
	return commonAncestor(l.Packages)
}

func commonAncestor(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return paths[0]
	}
	sort.Strings(paths)
	min, max := paths[0], paths[len(paths)-1]
	lastSlashIndex := 0
	for i := 0; i < len(min) && i < len(max); i++ {
		if min[i] != max[i] {
			return min[:lastSlashIndex]
		}
		if min[i] == '/' {
			lastSlashIndex = i
		}
	}
	return min
}

func (l *Library) String() string {
	return l.Name()
}

// FileURL attempts to determine the URL for a file in this library using
// go module name and version.
func (l *Library) FileURL(ctx context.Context, cl *source.Client, filePath string) (string, error) {
	if l == nil {
		return "", fmt.Errorf("library is nil")
	}
	wrap := func(err error) error {
		return fmt.Errorf("getting file URL in library %s: %w", l.Name(), err)
	}
	m := l.module
	if m == nil {
		return "", wrap(fmt.Errorf("empty go module info"))
	}
	if m.Dir == "" {
		return "", wrap(fmt.Errorf("empty go module dir"))
	}
	remote, err := source.ModuleInfo(ctx, cl, m.Path, m.Version)
	if err != nil {
		return "", wrap(err)
	}
	if m.Version == "" {
		// This always happens for the module in development.
		// Note#1 if we pass version=HEAD to source.ModuleInfo, github tag for modules not at the root
		// of the repo will be incorrect, because there's a convention that:
		// * I have a module at github.com/google/go-licenses/submod.
		// * The module is of version v1.0.0.
		// Then the github tag should be submod/v1.0.0.
		// In our case, if we pass HEAD as version, the result commit will be submod/HEAD which is incorrect.
		// Therefore, to workaround this problem, we directly set the commit after getting module info.
		//
		// Note#2 repos have different branches as default, some use the
		// master branch and some use the main branch. However, HEAD
		// always refers to the default branch, so it's better than
		// both of master/main when we do not know which branch is default.
		// Examples:
		// * https://github.com/google/go-licenses/blob/HEAD/LICENSE
		// points to latest commit of master branch.
		// * https://github.com/google/licenseclassifier/blob/HEAD/LICENSE
		// points to latest commit of main branch.
		remote.SetCommit("HEAD")
		klog.Warningf("module %s has empty version, defaults to HEAD. The license URL may be incorrect. Please verify!", m.Path)
	}
	relativePath, err := filepath.Rel(m.Dir, filePath)
	if err != nil {
		return "", wrap(err)
	}
	// TODO: there are still rare cases this may result in an incorrect URL.
	// https://github.com/google/go-licenses/issues/73#issuecomment-1005587408
	return remote.FileURL(relativePath), nil
}

func (l *Library) Version() string {
	if l.module != nil {
		return l.module.Version
	}
	return ""
}

// isStdLib returns true if this package is part of the Go standard library.
func isStdLib(pkg *packages.Package) bool {
	if pkg.Name == "unsafe" {
		// Special case unsafe stdlib, because it does not contain go files.
		return true
	}
	if len(pkg.GoFiles) == 0 {
		return false
	}
	prefix := build.Default.GOROOT
	sep := string(filepath.Separator)
	if !strings.HasSuffix(prefix, sep) {
		prefix += sep
	}
	return strings.HasPrefix(pkg.GoFiles[0], prefix)
}

// isTestBinary returns true iff pkg is a test binary.
func isTestBinary(pkg *packages.Package) bool {
	return strings.HasSuffix(pkg.PkgPath, ".test")
}
