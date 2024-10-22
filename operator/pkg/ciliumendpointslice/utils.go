// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"math/rand/v2"
	"strings"
)

// Generate random string for given length of characters.
func randomName(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = sequentialLetters[rand.IntN(len(sequentialLetters))]
	}
	return string(b)
}

// Generates unique random name for the CiliumEndpointSlice, the format
// of a CES name is similar to pod k8s naming convention "ces-123456789-abcde".
// First 3 letters indicates ces resource, followed by random letters.
func uniqueCESliceName(mapping *CESToCEPMapping) string {
	var sb strings.Builder
	for {
		rn1, rn2 := randomName(9), randomName(5)
		sb.Reset()
		sb.Grow(len(cesNamePrefix) + 1 + len(rn1) + 1 + len(rn2))
		sb.WriteString(cesNamePrefix)
		sb.WriteRune('-')
		sb.WriteString(rn1)
		sb.WriteRune('-')
		sb.WriteString(rn2)
		cesName := sb.String()
		if !mapping.hasCESName(CESName(cesName)) {
			return cesName
		}
	}
}
