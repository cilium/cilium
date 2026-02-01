// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColorersSequences(t *testing.T) {
	tests := []struct {
		colorerMode string
		want        []string
	}{
		{
			colorerMode: "never",
			want:        []string{},
		}, {
			colorerMode: "auto",
			want:        []string{},
		}, {
			colorerMode: "always",
			want: []string{
				"\x1b[31m", // red
				"\x1b[32m", // green
				"\x1b[34m", // blue
				"\x1b[36m", // cyan
				"\x1b[35m", // magenta
				"\x1b[33m", // yellow
				"\x1b[0m",  // reset
			},
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s => %v", tt.colorerMode, tt.want), func(t *testing.T) {
			colorer := newColorer(tt.colorerMode)
			got := colorer.sequences()
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
