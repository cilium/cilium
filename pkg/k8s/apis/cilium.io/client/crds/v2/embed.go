// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import "embed"

//go:embed *.yaml
var EmbedFS embed.FS
