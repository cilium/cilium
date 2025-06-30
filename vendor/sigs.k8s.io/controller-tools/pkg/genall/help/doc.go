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

// Package help contains utilities for actually writing out marker help.
//
// Namely, it contains a series of structs (and helpers for producing them)
// that represent a merged view of marker definition and help that can be used
// for consumption by the pretty subpackage (for terminal help) or serialized
// as JSON (e.g. for generating HTML help).
package help
