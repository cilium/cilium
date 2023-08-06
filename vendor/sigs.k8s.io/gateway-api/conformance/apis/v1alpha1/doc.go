//go:build experimental
// +build experimental

/*
Copyright 2023 The Kubernetes Authors.

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

// V1alpha1 includes alpha maturity API types and utilities for creating and
// handling the results of conformance test runs. These types are _only_
// intended for use by the conformance test suite OR external test suites that
// are written in Golang and execute the conformance test suite as a Golang
// library.
//
// Note that currently all sub-packages are considered "experimental" in that
// they aren't intended for general use or to be distributed as part of a
// release so there is no way to use them by default when using the Golang
// library at this time. If you don't know for sure that you want to use these
// features, then you should not use them. If you would like to opt into these
// unreleased features use Go build tags to enable them, e.g.:
//
//   $ GOFLAGS='-tags=experimental' go test ./conformance/... -args ${CONFORMANCE_ARGS}
//
// Please note that everything here is considered experimental and subject to
// change. Expect breaking changes and/or complete removals if you start using
// them.

package v1alpha1
