// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build !race

package pathtemplate

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchDoesNotAllocate checks that the split buffer stays on the stack.
// Match runs once per HTTP flow, so one allocation here is one per request in
// the agent. Skipped under -race, which allocates on its own.
//
// The deepest template sizes the buffer, so the config is varied along with the
// path. Testing shallow configs alone missed a deep template pushing every
// match onto the heap, short paths included.
func TestMatchDoesNotAllocate(t *testing.T) {
	full := make([]string, 0, MaxTemplates)
	for i := range MaxTemplates {
		full = append(full, fmt.Sprintf("/route/%d/items/{id}", i))
	}
	full[MaxTemplates-1] = "/static/{rest...}"

	atCap := "/" + strings.Repeat("seg/", MaxTemplateSegments-2) + "{id}"

	configs := []struct {
		name      string
		templates []string
	}{
		{"shallow templates", full},
		{"full list holding a template at the segment cap",
			append(slices.Clone(full[:MaxTemplates-1]), atCap)},
		{"one template at the segment cap", []string{atCap}},
	}

	paths := []string{
		"/route/0/items/abc",
		"/route/50/items/abc",
		"/healthz",
		"/static/css/site.css",
		"/static/" + strings.Repeat("a/", 64) + "site.css",
		"/" + strings.Repeat("seg/", MaxTemplateSegments-2) + "abc",
		strings.Repeat("/", 4000),
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			m, err := Compile(cfg.templates)
			require.NoError(t, err)

			for _, path := range paths {
				got := testing.AllocsPerRun(100, func() {
					m.Match(path)
				})
				assert.Zerof(t, got, "Match(%.32q) allocated", path)
			}
		})
	}
}
