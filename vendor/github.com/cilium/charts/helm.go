// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helm

import (
	"embed"
)

var (
	//go:embed *.tgz
	HelmFS embed.FS
)
