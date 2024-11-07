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

// Package pretty contains utilities for formatting terminal help output,
// and a use of those to display marker help.
//
// # Terminal Output
//
// The Span interface and Table struct allow you to construct tables with
// colored formatting, without causing ANSI formatting characters to mess up width
// calculations.
//
// # Marker Help
//
// The MarkersSummary prints a summary table for marker help, while the MarkersDetails
// prints out more detailed information, with explainations of the individual marker fields.
package pretty
