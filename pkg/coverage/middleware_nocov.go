// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !cover

package coverage

import "net/http"

func NewCoverageMiddleware(next http.Handler) http.Handler {
	return next
}
