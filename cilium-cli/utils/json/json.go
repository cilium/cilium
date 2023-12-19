// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import "strings"

func EscapePatchString(str string) string {
	// From https://www.rfc-editor.org/rfc/rfc6901#section-3:
	// Because the characters '~' (%x7E) and '/' (%x2F) have special meanings in JSON Pointer,
	// '~' needs to be encoded as '~0' and '/' needs to be encoded as '~1' when these characters
	// appear in a reference token.
	str = strings.ReplaceAll(str, "~", "~0")
	str = strings.ReplaceAll(str, "/", "~1")
	return str
}
