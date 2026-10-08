package ndp

import (
	"fmt"
)

// fuzz is a shared function for go-fuzz and tests that verify go-fuzz bugs
// are fixed.
func fuzz(data []byte) int {
	m, err := ParseMessage(data)
	if err != nil {
		return 0
	}

	b2, err := MarshalMessage(m)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal: %v", err))
	}

	if _, err := ParseMessage(b2); err != nil {
		panic(fmt.Sprintf("failed to parse: %v", err))
	}

	return 1
}
