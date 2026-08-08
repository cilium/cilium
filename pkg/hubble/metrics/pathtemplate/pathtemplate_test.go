// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package pathtemplate

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileValid(t *testing.T) {
	tests := []struct {
		name      string
		templates []string
	}{
		{"root", []string{"/"}},
		{"literal", []string{"/api/v1/users"}},
		{"placeholder", []string{"/api/v1/users/{id}"}},
		{"several placeholders", []string{"/api/v1/users/{userID}/orders/{orderID}"}},
		{"tail", []string{"/static/{rest...}"}},
		{"tail only", []string{"/{rest...}"}},
		{"trailing slash", []string{"/api/v1/users/"}},
		{"name with underscore", []string{"/api/{_id}"}},
		{"name with digits", []string{"/api/{id2}"}},
		{"percent encoded literal", []string{"/reports/my%20report"}},
		{"escaped braces are a literal", []string{"/api/%7Blegacy%7D"}},
		{"dot segments", []string{"/a/../b"}},
		{"several templates", []string{"/a", "/a/{id}", "/a/{id}/b", "/{rest...}"}},
		// Nothing is captured, so unlike net/http.ServeMux a name may repeat.
		{"repeated placeholder name", []string{"/users/{id}/orders/{id}"}},
		// Only templates matching the same set of paths are duplicates.
		{"placeholder and tail", []string{"/a/{x}", "/a/{x...}"}},
		{"placeholder and empty segment", []string{"/a/{x}", "/a/"}},
		{"same shape, different literals", []string{"/a/{x}", "/b/{x}"}},
		{"same shape, different depths", []string{"/a/{x}", "/a/{x}/{y}"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Compile(tt.templates)
			require.NoError(t, err)
			require.Equal(t, len(tt.templates), m.Len())
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name      string
		templates []string
		wantErr   string
	}{
		{"empty list", nil, "no templates configured"},
		{"empty template", []string{""}, "template is empty"},
		{"no leading slash", []string{"api/v1"}, "template must start with '/'"},
		{"placeholder after a literal", []string{"/b_{bucket}"}, "must span a whole segment"},
		{"placeholder before a literal", []string{"/{bucket}_b"}, "must span a whole segment"},
		{"two placeholders in a segment", []string{"/{a}{b}"}, "must span a whole segment"},
		{"unclosed placeholder", []string{"/{id"}, "must span a whole segment"},
		{"unopened placeholder", []string{"/id}"}, "must span a whole segment"},
		{"nested braces", []string{"/{{id}}"}, "must span a whole segment"},
		{"tail not last", []string{"/static/{rest...}/more"}, "must be last"},
		{"tail before an empty segment", []string{"/static/{rest...}/"}, "must be last"},
		{"empty name", []string{"/{}"}, "invalid placeholder name"},
		{"empty tail name", []string{"/{...}"}, "invalid placeholder name"},
		{"name starting with a digit", []string{"/{1id}"}, "invalid placeholder name"},
		{"name with a hyphen", []string{"/{user-id}"}, "invalid placeholder name"},
		{"name with a dot", []string{"/{user.id}"}, "invalid placeholder name"},
		{"non-ascii name", []string{"/{идентификатор}"}, "invalid placeholder name"},
		{"pattern in a placeholder", []string{"/users/{id:[0-9]+}"}, "patterns in placeholders are not supported"},
		{"pattern in a tail", []string{"/users/{id:.*...}"}, "patterns in placeholders are not supported"},
		// ":" is checked before the braces the pattern holds, so the error
		// names the real problem.
		{"pattern holding braces", []string{"/users/{id:[0-9]{2}}"}, "patterns in placeholders are not supported"},
		{"duplicate", []string{"/users/{id}", "/users/{id}"}, "matches the same paths as templates[0]"},
		{"duplicate but for the name", []string{"/users/{id}", "/users/{user}"}, "matches the same paths as templates[0]"},
		{"duplicate tail but for the name", []string{"/s/{rest...}", "/s/{other...}"}, "matches the same paths as templates[0]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Compile(tt.templates)
			require.ErrorContains(t, err, tt.wantErr)
			require.Nil(t, m)
		})
	}
}

func TestCompileReportsEveryError(t *testing.T) {
	_, err := Compile([]string{"/ok", "/b_{bucket}", "/{1id}", "/ok"})
	require.Error(t, err)
	assert.ErrorContains(t, err, `templates[1] ("/b_{bucket}")`)
	assert.ErrorContains(t, err, `templates[2] ("/{1id}")`)
	assert.ErrorContains(t, err, `templates[3] ("/ok")`)
}

func TestCompileTemplateLimit(t *testing.T) {
	templates := make([]string, 0, MaxTemplates+1)
	for i := range MaxTemplates + 1 {
		templates = append(templates, fmt.Sprintf("/route/%d", i))
	}

	m, err := Compile(templates[:MaxTemplates])
	require.NoError(t, err)
	require.Equal(t, MaxTemplates, m.Len())

	_, err = Compile(templates)
	require.ErrorContains(t, err, "101 templates configured, at most 100 are supported")
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name      string
		templates []string
		path      string
		want      string
	}{
		{
			name:      "declaration order beats specificity",
			templates: []string{"/api/{rest...}", "/api/v1/users"},
			path:      "/api/v1/users",
			want:      "/api/{rest...}",
		},
		{
			name:      "reordered, the specific template wins",
			templates: []string{"/api/v1/users", "/api/{rest...}"},
			path:      "/api/v1/users",
			want:      "/api/v1/users",
		},
		{
			name:      "a shadowing template still matches other paths",
			templates: []string{"/api/v1/users", "/api/{rest...}"},
			path:      "/api/v2/users",
			want:      "/api/{rest...}",
		},
		{
			name:      "path longer than the template",
			templates: []string{"/api/v1"},
			path:      "/api/v1/users",
			want:      "",
		},
		{
			name:      "path shorter than the template",
			templates: []string{"/api/v1/users"},
			path:      "/api/v1",
			want:      "",
		},
		{
			name:      "trailing slash on the path",
			templates: []string{"/api/v1/users"},
			path:      "/api/v1/users/",
			want:      "",
		},
		{
			name:      "trailing slash on the template",
			templates: []string{"/api/v1/users/"},
			path:      "/api/v1/users",
			want:      "",
		},
		{
			name:      "trailing slash on both",
			templates: []string{"/api/v1/users/"},
			path:      "/api/v1/users/",
			want:      "/api/v1/users/",
		},
		{
			name:      "root",
			templates: []string{"/"},
			path:      "/",
			want:      "/",
		},
		{
			name:      "root against a deeper path",
			templates: []string{"/"},
			path:      "/api",
			want:      "",
		},
		{
			name:      "placeholder takes one segment",
			templates: []string{"/api/v1/users/{id}"},
			path:      "/api/v1/users/abc",
			want:      "/api/v1/users/{id}",
		},
		{
			name:      "another value collapses onto the same template",
			templates: []string{"/api/v1/users/{id}"},
			path:      "/api/v1/users/xyz",
			want:      "/api/v1/users/{id}",
		},
		{
			name:      "placeholder against an empty segment",
			templates: []string{"/api/v1/users/{id}"},
			path:      "/api/v1/users/",
			want:      "",
		},
		{
			name:      "placeholder against a missing segment",
			templates: []string{"/api/v1/users/{id}"},
			path:      "/api/v1/users",
			want:      "",
		},
		{
			name:      "placeholder against two segments",
			templates: []string{"/api/v1/users/{id}"},
			path:      "/api/v1/users/abc/orders",
			want:      "",
		},
		{
			name:      "placeholder mid-template",
			templates: []string{"/api/v1/users/{id}/orders"},
			path:      "/api/v1/users/abc/orders",
			want:      "/api/v1/users/{id}/orders",
		},
		{
			name:      "tail takes several segments",
			templates: []string{"/static/{rest...}"},
			path:      "/static/css/site.css",
			want:      "/static/{rest...}",
		},
		{
			name:      "tail takes one segment",
			templates: []string{"/static/{rest...}"},
			path:      "/static/site.css",
			want:      "/static/{rest...}",
		},
		{
			name:      "tail takes an empty segment",
			templates: []string{"/static/{rest...}"},
			path:      "/static/",
			want:      "/static/{rest...}",
		},
		{
			name:      "tail has nothing to take",
			templates: []string{"/static/{rest...}"},
			path:      "/static",
			want:      "",
		},
		{
			name:      "catch-all tail",
			templates: []string{"/{rest...}"},
			path:      "/anything/at/all",
			want:      "/{rest...}",
		},
		{
			name:      "catch-all tail on the root",
			templates: []string{"/{rest...}"},
			path:      "/",
			want:      "/{rest...}",
		},

		// These describe the matcher on its own. Envoy normalizes the path
		// before Hubble records it, unless http-normalize-path is turned off,
		// so they are not promises about what happens end to end.
		{
			name:      "escaped space against an escaped space",
			templates: []string{"/reports/my%20report"},
			path:      "/reports/my%20report",
			want:      "/reports/my%20report",
		},
		{
			name:      "escaped space against a decoded space",
			templates: []string{"/reports/my report"},
			path:      "/reports/my%20report",
			want:      "",
		},
		{
			name:      "decoded space against an escaped space",
			templates: []string{"/reports/my%20report"},
			path:      "/reports/my report",
			want:      "",
		},
		{
			name:      "escaped slash stays inside a segment",
			templates: []string{"/api/v1/{user}/orders"},
			path:      "/api/v1/users%2Fadmin/orders",
			want:      "/api/v1/{user}/orders",
		},
		{
			name:      "escaped slash does not add a segment",
			templates: []string{"/api/v1/users/{id}/orders"},
			path:      "/api/v1/users%2Fadmin/orders",
			want:      "",
		},
		{
			name:      "escaped dot segments are not dot segments",
			templates: []string{"/a/b"},
			path:      "/a/%2e%2e/a/b",
			want:      "",
		},
		{
			name:      "dot segments are literals",
			templates: []string{"/a/../b"},
			path:      "/a/../b",
			want:      "/a/../b",
		},
		{
			name:      "dot segments are not resolved",
			templates: []string{"/b"},
			path:      "/a/../b",
			want:      "",
		},
		{
			name:      "duplicate slashes are not merged",
			templates: []string{"/a/b"},
			path:      "//a//b",
			want:      "",
		},
		{
			name:      "escaped non-ascii segment",
			templates: []string{"/caf%C3%A9/detail"},
			path:      "/caf%C3%A9/detail",
			want:      "/caf%C3%A9/detail",
		},
		{
			name:      "matching is case sensitive",
			templates: []string{"/api/v1/Users"},
			path:      "/api/v1/users",
			want:      "",
		},
		{
			name:      "empty path",
			templates: []string{"/api/v1/users/{id}"},
			path:      "",
			want:      "",
		},
		{
			name:      "relative path",
			templates: []string{"/api/v1/users/{id}"},
			path:      "api/v1/users/abc",
			want:      "",
		},
		{
			name:      "no template matches",
			templates: []string{"/api/v1/users/{id}", "/api/v1/orders/{id}"},
			path:      "/healthz",
			want:      "",
		},

		// Match only splits as far as the longest template can tell paths
		// apart. These run past that point.
		{
			name:      "path deeper than every template",
			templates: []string{"/api/v1/users/{id}", "/healthz"},
			path:      "/api/v1/users/abc/orders/1/items/2/detail",
			want:      "",
		},
		{
			name:      "tail takes a path deeper than every template",
			templates: []string{"/api/v1/users/{id}", "/api/{rest...}"},
			path:      "/api/v1/users/abc/orders/1/items/2/detail",
			want:      "/api/{rest...}",
		},
		{
			name:      "path one segment past the deepest template",
			templates: []string{"/a/{x}"},
			path:      "/a/b/c",
			want:      "",
		},
		{
			name:      "deep path against a shallow tail",
			templates: []string{"/static/{rest...}"},
			path:      "/static/" + strings.Repeat("a/", 64) + "site.css",
			want:      "/static/{rest...}",
		},
		{
			name:      "slash flood",
			templates: []string{"/api/v1/users/{id}", "/healthz"},
			path:      strings.Repeat("/", 4000),
			want:      "",
		},
		{
			name:      "slash flood against a tail",
			templates: []string{"/{rest...}"},
			path:      strings.Repeat("/", 4000),
			want:      "/{rest...}",
		},
		{
			// maxStackSegments-1 segments is the longest template that still
			// splits into the stack buffer, and it fills it exactly.
			name:      "template filling the stack buffer",
			templates: []string{"/" + strings.Repeat("seg/", maxStackSegments-3) + "{id}"},
			path:      "/" + strings.Repeat("seg/", maxStackSegments-3) + "abc",
			want:      "/" + strings.Repeat("seg/", maxStackSegments-3) + "{id}",
		},
		{
			name:      "template one segment past the stack buffer",
			templates: []string{"/" + strings.Repeat("seg/", maxStackSegments-2) + "{id}"},
			path:      "/" + strings.Repeat("seg/", maxStackSegments-2) + "abc",
			want:      "/" + strings.Repeat("seg/", maxStackSegments-2) + "{id}",
		},
		{
			name:      "template deeper than the stack buffer",
			templates: []string{"/" + strings.Repeat("seg/", maxStackSegments+4) + "{id}"},
			path:      "/" + strings.Repeat("seg/", maxStackSegments+4) + "abc",
			want:      "/" + strings.Repeat("seg/", maxStackSegments+4) + "{id}",
		},
		{
			name:      "deep template against a path one segment short",
			templates: []string{"/" + strings.Repeat("seg/", maxStackSegments+4) + "{id}"},
			path:      "/" + strings.Repeat("seg/", maxStackSegments+4),
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Compile(tt.templates)
			require.NoError(t, err)

			got, ok := m.Match(tt.path)
			assert.Equal(t, tt.want != "", ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMatchReturnsConfiguredValues is the cardinality limit written as a test.
func TestMatchReturnsConfiguredValues(t *testing.T) {
	templates := []string{"/api/v1/users/{id}", "/api/v1/users/{id}/orders/{orderID}", "/static/{rest...}"}
	m, err := Compile(templates)
	require.NoError(t, err)

	paths := []string{
		"/api/v1/users/abc",
		"/api/v1/users/xyz",
		"/api/v1/users/abc/orders/1",
		"/static/css/site.css",
		"/static/",
	}
	for _, path := range paths {
		got, ok := m.Match(path)
		require.Truef(t, ok, "expected %q to match", path)
		assert.Containsf(t, templates, got, "%q produced an unconfigured label value", path)
	}
}

func TestNilMatcher(t *testing.T) {
	var m *Matcher
	got, ok := m.Match("/api/v1/users/abc")
	assert.False(t, ok)
	assert.Empty(t, got)
	assert.Equal(t, 0, m.Len())
	assert.Empty(t, m.Shadowed())
}

func TestShadowed(t *testing.T) {
	tests := []struct {
		name      string
		templates []string
		want      []Shadow
	}{
		{
			name:      "a tail shadows everything below it",
			templates: []string{"/api/{rest...}", "/api/v1/users", "/api/v1/users/{id}"},
			want: []Shadow{
				{Index: 1, Template: "/api/v1/users", ByIndex: 0, ByTemplate: "/api/{rest...}"},
				{Index: 2, Template: "/api/v1/users/{id}", ByIndex: 0, ByTemplate: "/api/{rest...}"},
			},
		},
		{
			name:      "a catch-all shadows the whole list",
			templates: []string{"/{rest...}", "/healthz"},
			want:      []Shadow{{Index: 1, Template: "/healthz", ByIndex: 0, ByTemplate: "/{rest...}"}},
		},
		{
			name:      "a placeholder shadows a literal at the same depth",
			templates: []string{"/users/{id}", "/users/me"},
			want:      []Shadow{{Index: 1, Template: "/users/me", ByIndex: 0, ByTemplate: "/users/{id}"}},
		},
		{
			name:      "the shadowing template is reported, not the first template",
			templates: []string{"/healthz", "/users/{id}", "/users/me"},
			want:      []Shadow{{Index: 2, Template: "/users/me", ByIndex: 1, ByTemplate: "/users/{id}"}},
		},
		{
			name:      "ordered narrowest first, nothing is shadowed",
			templates: []string{"/api/v1/users", "/api/v1/users/{id}", "/api/{rest...}"},
		},
		{
			name:      "a literal does not shadow a placeholder",
			templates: []string{"/users/me", "/users/{id}"},
		},
		{
			name:      "a placeholder does not shadow an empty segment",
			templates: []string{"/users/{id}", "/users/"},
		},
		{
			name:      "a placeholder does not shadow a tail",
			templates: []string{"/static/{one}", "/static/{rest...}"},
		},
		{
			name:      "a shallower tail does not shadow a deeper one",
			templates: []string{"/a/{rest...}", "/a/b/{rest...}"},
			want:      []Shadow{{Index: 1, Template: "/a/b/{rest...}", ByIndex: 0, ByTemplate: "/a/{rest...}"}},
		},
		{
			name:      "a deeper tail does not shadow a shallower one",
			templates: []string{"/a/b/{rest...}", "/a/{rest...}"},
		},
		{
			name:      "different literals never shadow",
			templates: []string{"/a/{x}", "/b/{x}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Compile(tt.templates)
			require.NoError(t, err)
			assert.Equal(t, tt.want, m.Shadowed())
		})
	}
}

// TestShadowedAgreesWithMatch checks that a template reported as shadowed never
// wins a match, whatever the path.
func TestShadowedAgreesWithMatch(t *testing.T) {
	templates := []string{
		"/healthz", "/api/{rest...}", "/api/v1/users", "/api/v1/users/{id}",
		"/users/{id}", "/users/me", "/static/{one}", "/static/{rest...}",
	}
	m, err := Compile(templates)
	require.NoError(t, err)

	shadowed := make(map[string]bool)
	for _, s := range m.Shadowed() {
		shadowed[s.Template] = true
	}
	require.NotEmpty(t, shadowed)

	paths := []string{
		"/", "/healthz", "/api", "/api/", "/api/v1", "/api/v1/users",
		"/api/v1/users/", "/api/v1/users/abc", "/api/v1/users/abc/orders",
		"/users", "/users/", "/users/me", "/users/abc", "/static",
		"/static/", "/static/one", "/static/a/b/c",
	}
	for _, path := range paths {
		if got, ok := m.Match(path); ok {
			assert.Falsef(t, shadowed[got], "%q matched shadowed template %q", path, got)
		}
	}
}

// TestMatchConcurrent checks that a compiled Matcher is safe to use from
// several goroutines. Run it under -race.
func TestMatchConcurrent(t *testing.T) {
	m, err := Compile([]string{"/api/v1/users/{id}", "/api/v1/users/{id}/orders", "/static/{rest...}"})
	require.NoError(t, err)

	paths := []string{"/api/v1/users/abc", "/api/v1/users/abc/orders", "/static/css/site.css", "/healthz"}
	want := make([]string, len(paths))
	for i, path := range paths {
		want[i], _ = m.Match(path)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				for i, path := range paths {
					if got, _ := m.Match(path); got != want[i] {
						assert.Equalf(t, want[i], got, "Match(%q) raced", path)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

// BenchmarkMatch uses a full template list, since the matcher sits on the HTTP
// metrics hot path.
func BenchmarkMatch(b *testing.B) {
	benchmarks := []struct {
		name string
		path string
	}{
		{"first template", "/route/0/items/abc"},
		{"last template", fmt.Sprintf("/route/%d/items/abc", MaxTemplates-1)},
		{"miss", "/healthz"},
	}

	templates := make([]string, 0, MaxTemplates)
	for i := range MaxTemplates {
		templates = append(templates, fmt.Sprintf("/route/%d/items/{id}", i))
	}
	m, err := Compile(templates)
	require.NoError(b, err)

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m.Match(bm.path)
			}
		})
	}
}

func BenchmarkMatchDeepTail(b *testing.B) {
	m, err := Compile([]string{"/static/{rest...}"})
	require.NoError(b, err)

	path := "/static/" + strings.Repeat("a/", 32) + "site.css"
	b.ReportAllocs()
	for b.Loop() {
		m.Match(path)
	}
}

// BenchmarkMatchLongPath keeps the cost of a match tied to the templates, not
// to the request. The client picks the path, and Envoy allows request headers
// up to 60 KiB by default.
func BenchmarkMatchLongPath(b *testing.B) {
	benchmarks := []struct {
		name string
		path string
	}{
		{"deep", "/" + strings.Repeat("a/", 2000)},
		{"slash flood", strings.Repeat("/", 4000)},
	}

	m, err := Compile([]string{"/api/v1/users/{id}", "/api/v1/users/{id}/orders", "/healthz"})
	require.NoError(b, err)

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m.Match(bm.path)
			}
		})
	}
}
