// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build !race

package pathtemplate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchDoesNotAllocate checks that the split buffer stays on the stack.
// Match runs once per HTTP flow, so one allocation here is one per request in
// the agent. Skipped under -race, which allocates on its own.
func TestMatchDoesNotAllocate(t *testing.T) {
	templates := make([]string, 0, MaxTemplates)
	for i := range MaxTemplates {
		templates = append(templates, fmt.Sprintf("/route/%d/items/{id}", i))
	}
	templates[MaxTemplates-1] = "/static/{rest...}"
	m, err := Compile(templates)
	require.NoError(t, err)

	paths := []string{
		"/route/0/items/abc",
		"/route/50/items/abc",
		"/healthz",
		"/static/css/site.css",
		"/static/" + strings.Repeat("a/", 64) + "site.css",
		strings.Repeat("/", 4000),
	}

	for _, path := range paths {
		got := testing.AllocsPerRun(100, func() {
			m.Match(path)
		})
		assert.Zerof(t, got, "Match(%.32q) allocated", path)
	}
}
