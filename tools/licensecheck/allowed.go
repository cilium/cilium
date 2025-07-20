// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

// See https://github.com/cncf/foundation/blob/main/allowed-third-party-license-policy.md
var allowedLicenses = []string{
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-2-Clause-FreeBSD",
	"BSD-3-Clause",
	"ISC",
	"MIT",
	"PostgreSQL",
	"Python-2.0",
	"X11",
	"Zlib",
}

// See https://github.com/cncf/foundation/tree/main/license-exceptions
// Do not add all exceptions from the above link, only packages that we
// actually use.
var pkgExceptions = []string{
	"github.com/hashicorp/errwrap",
	"github.com/hashicorp/go-cleanhttp",
	"github.com/hashicorp/go-immutable-radix",
	"github.com/hashicorp/go-multierror",
	"github.com/hashicorp/go-rootcerts",
	"github.com/hashicorp/golang-lru",
	"github.com/hashicorp/hcl",
	"github.com/hashicorp/serf/coordinate",
}
