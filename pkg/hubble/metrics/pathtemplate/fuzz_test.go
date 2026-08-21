// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package pathtemplate

import (
	"slices"
	"testing"
)

// FuzzCompileAndMatch checks the two rules that keep the "path" label bounded.
// A match only ever returns a configured template, and a compiled list holds
// every template that was configured. Two templates are fuzzed instead of one,
// so ordering, duplicate rejection and shadowing are covered as well.
func FuzzCompileAndMatch(f *testing.F) {
	seeds := []struct{ first, second, path string }{
		{"/", "/api", "/"},
		{"/api/v1/users/{id}", "/api/v1/users/me", "/api/v1/users/abc"},
		{"/api/v1/users/{id}/orders", "/api/{rest...}", "/api/v1/users/abc/orders"},
		{"/static/{rest...}", "/static/css/{file}", "/static/css/site.css"},
		{"/{rest...}", "/healthz", "/anything"},
		{"/reports/my%20report", "/api/%7Blegacy%7D", "/reports/my%20report"},
		{"/b_{bucket}", "/", "/b_1"},
		{"/{rest...}/more", "/", "/a/more"},
		{"/{1id}", "/", "/1"},
		{"/users/{id:[0-9]+}", "/", "/users/1"},
		{"/a/{x}", "/a/{y}", "/a/b"},
		{"", "", ""},
		{"api/v1", "/", "api/v1"},
	}
	for _, seed := range seeds {
		f.Add(seed.first, seed.second, seed.path)
	}

	f.Fuzz(func(t *testing.T, first, second, path string) {
		templates := []string{first, second}
		m, err := Compile(templates)
		if err != nil {
			return
		}
		if m.Len() != len(templates) {
			t.Fatalf("Compile(%q) kept %d templates, want %d", templates, m.Len(), len(templates))
		}

		shadowed := make(map[int]bool)
		for _, s := range m.Shadowed() {
			if s.Index <= s.ByIndex {
				t.Fatalf("Shadowed reported templates[%d] shadowed by the later templates[%d]", s.Index, s.ByIndex)
			}
			if s.Template != templates[s.Index] || s.ByTemplate != templates[s.ByIndex] {
				t.Fatalf("Shadowed reported %q/%q, want %q/%q",
					s.Template, s.ByTemplate, templates[s.Index], templates[s.ByIndex])
			}
			shadowed[s.Index] = true
		}

		got, ok := m.Match(path)
		if !ok {
			if got != "" {
				t.Fatalf("Match(%q) returned %q on a miss, want an empty value", path, got)
			}
			return
		}
		i := slices.Index(templates, got)
		if i < 0 {
			t.Fatalf("Match(%q) returned %q, want one of %q", path, got, templates)
		}
		// If a shadowed template could win, the report would send someone off
		// to reorder a list that already does what they want.
		if shadowed[i] {
			t.Fatalf("Match(%q) returned templates[%d] (%q), reported as shadowed", path, i, got)
		}
	})
}
