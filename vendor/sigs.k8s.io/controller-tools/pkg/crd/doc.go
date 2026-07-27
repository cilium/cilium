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

// Package crd contains utilities for generating CustomResourceDefinitions and
// their corresponding OpenAPI validation schemata.
//
// # Markers
//
// Markers live under the markers subpackage.  Two types of markers exist:
// those that modify schema generation (for validation), and those that modify
// the rest of the CRD.  See the subpackage for more information and all
// supported markers.
//
// # Collecting Types and Generating CRDs
//
// The Parser is the entrypoint for collecting the information required to
// generate CRDs.  Like loader and collector, its methods are idemptotent, not
// doing extra work if called multiple times.
//
// Parser's method start with Need.  Calling NeedXYZ indicates that XYZ should
// be made present in the eqivalent field in the Parser, where it can then be
// loaded from.  Each Need method will in turn call Need on anything it needs.
//
// In general, root packages should first be loaded into the Parser with
// NeedPackage.  Then, CRDs can be generated with NeedCRDFor.
//
// Errors are generally attached directly to the relevant Package with
// AddError.
//
// # Known Packages
//
// There are a few types from Kubernetes that have special meaning, but don't
// have validation markers attached.  Those specific types have overrides
// listed in KnownPackages that can be added as overrides to any parser.
//
// # Flattening
//
// Once schemata are generated, they can be used directly by external tooling
// (like JSONSchema validators), but must first be "flattened" to not contain
// references before use in a CRD (Kubernetes doesn't allow references in the
// CRD's validation schema).
//
// The Flattener built in to the Parser takes care of flattening out references
// when requesting the CRDs, but can be invoked manually.  It will not modify
// the input schemata.
//
// Flattened schemata may further be passed to FlattenEmbedded to remove the
// use of AllOf (which is used to describe embedded struct fields when
// references are in use).  This done automatically when fetching CRDs.
package crd
