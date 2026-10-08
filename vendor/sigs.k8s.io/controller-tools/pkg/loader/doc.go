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

// Package loader defines helpers for loading packages from sources.  It wraps
// go/packages, allow incremental loading of source code and manual control
// over which packages get type-checked.  This allows for faster loading in
// cases where you don't actually care about certain imports.
//
// Because it uses go/packages, it's modules-aware, and works in both modules-
// and non-modules environments.
//
// # Loading
//
// The main entrypoint for loading is LoadRoots, which traverse the package
// graph starting at the given patterns (file, package, path, or ...-wildcard,
// as one might pass to go list).  Packages beyond the roots can be accessed
// via the Imports() method.  Packages are initially loaded with export data
// paths, filenames, and imports.
//
// Packages are suitable for comparison, as each unique package only ever has
// one *Package object returned.
//
// # Syntax and TypeChecking
//
// ASTs and type-checking information can be loaded with NeedSyntax and
// NeedTypesInfo, respectively.  Both are idempotent -- repeated calls will
// simply re-use the cached contents.  Note that NeedTypesInfo will *only* type
// check the current package -- if you want to type-check imports as well,
// you'll need to type-check them first.
//
// # Reference Pruning and Recursive Checking
//
// In order to type-check using only the packages you care about, you can use a
// TypeChecker.  TypeChecker will visit each top-level type declaration,
// collect (optionally filtered) references, and type-check references
// packages.
//
// # Errors
//
// Errors can be added to each package.  Use ErrFromNode to create an error
// from an AST node.  Errors can then be printed (complete with file and
// position information) using PrintErrors, optionally filtered by error type.
// It's generally a good idea to filter out TypeErrors when doing incomplete
// type-checking with TypeChecker.  You can use MaybeErrList to return multiple
// errors if you need to return an error instead of adding it to a package.
// AddError will later unroll it into individual errors.
package loader
