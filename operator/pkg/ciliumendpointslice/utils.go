package ciliumendpointslice

import (
	"fmt"
	"math/rand"
)

// Generate random string for given length of characters.
func randomName(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = sequentialLetters[rand.Intn(len(sequentialLetters))]
	}
	return string(b)
}

// Generates unique random name for the CiliumEndpointSlice, the format
// of a CES name is similar to pod k8s naming convention "ces-123456789-abcde".
// First 3 letters indicates ces resource, followed by random letters.
func uniqueCESliceName(mapping *CESToCEPMapping) string {
	var cesName string
	for {
		cesName = fmt.Sprintf("%s-%s-%s", cesNamePrefix, randomName(9), randomName(5))
		if !mapping.hasCESName(CESName(cesName)) {
			return cesName
		}
	}
}
