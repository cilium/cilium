// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package id

// Identifiers is a collection of attributes that identify the Endpoint through
// different systems. For examples of the type of Identifiers, see PrefixType.
type Identifiers map[PrefixType]string
