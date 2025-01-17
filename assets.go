// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Assets provides access to some top-level files into the tree to support
// tooling for Cilium development.
package assets

import (
	_ "embed"
)

//go:embed CODEOWNERS
var CodeOwnersRaw string
