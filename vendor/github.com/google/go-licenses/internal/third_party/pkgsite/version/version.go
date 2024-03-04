// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version handles version types.
package version

import (
	"regexp"
	"strings"
)

const (
	// Latest signifies the latest available version in requests to the
	// proxy client.
	Latest = "latest"

	// Main represents the main branch.
	Main = "main"

	// Master represents the master branch.
	Master = "master"
)

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+incompatible)?$`)

// IsPseudo reports whether a valid version v is a pseudo-version.
// Modified from src/cmd/go/internal/modfetch.
func IsPseudo(v string) bool {
	return strings.Count(v, "-") >= 2 && pseudoVersionRE.MatchString(v)
}
