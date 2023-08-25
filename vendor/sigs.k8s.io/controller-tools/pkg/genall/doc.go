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

// Package genall defines entrypoints for generation tools to hook into and
// share the same set of parsing, typechecking, and marker information.
//
// Generators
//
// Each Generator knows how to register its markers into a central Registry,
// and then how to generate output using a Collector and some root packages.
// Each generator can be considered to be the output type of a marker, for easy
// command line parsing.
//
// Output and Input
//
// Generators output artifacts via an OutputRule.  OutputRules know how to
// write output for different package-associated (code) files, as well as
// config files.  Each OutputRule should also be considered to be the output
// type as a marker, for easy command-line parsing.
//
// OutputRules groups together an OutputRule per generator, plus a default
// output rule for any not explicitly specified.
//
// OutputRules are defined for stdout, file writing, and sending to /dev/null
// (useful for doing "type-checking" without actually saving the results).
//
// InputRule defines custom input loading, but its shared across all
// Generators.  There's currently only a filesystem implementation.
//
// Runtime and Context
//
// Runtime maps together Generators, and constructs "contexts" which provide
// the common collector and roots, plus the output rule for that generator, and
// a handle for reading files (like boilerplate headers).
//
// It will run all associated generators, printing errors and automatically
// skipping type-checking errors (since those are commonly caused by the
// partial type-checking of loader.TypeChecker).
//
// Options
//
// The FromOptions (and associated helpers) function makes it easy to use generators
// and output rules as markers that can be parsed from the command line, producing
// a registry from command line args.
package genall
