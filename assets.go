// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Cilium provides access to top-level files in the tree for Cilium development.
package cilium

import (
	_ "embed"
)

//go:embed CODEOWNERS
var CodeOwnersRaw string
