// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"reflect"
	"testing"
)

func Test_translateSelector(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "simple",
			in:   "foo",
			want: "any.foo",
		},
		{
			name: "multiple",
			in:   "foo, bar",
			want: "any.foo, any.bar",
		},
		{
			name: "with prefix",
			in:   "k8s:foo, bar",
			want: "k8s.foo, any.bar",
		},
		{
			name: "with negation",
			in:   "k8s:foo, !bar",
			want: "k8s.foo, !any.bar",
		},
		{
			name: "with negation",
			in:   "k8s:foo, !bar",
			want: "k8s.foo, !any.bar",
		},
		{
			name: "match value",
			in:   "foo, bar=buzz",
			want: "any.foo, any.bar=buzz",
		},
		{
			name: "don't match value",
			in:   "foo, bar!= buzz",
			want: "any.foo, any.bar!= buzz",
		},
		{
			name: "in values",
			in:   "foo in (a,b,c)",
			want: "any.foo in (a,b,c)",
		},
		{
			name: "notin values",
			in:   "foo notin   (a,b,c)",
			want: "any.foo notin   (a,b,c)",
		},
		{
			name: "with dots",
			in:   "foo.example.com, bar.example.com=buzz",
			want: "any.foo.example.com, any.bar.example.com=buzz",
		},
		{
			name: "dots and colons in value",
			in:   "foo.example.com=some:other.thing, bar.example.com=buzz:any:thing.example.org",
			want: "any.foo.example.com=some:other.thing, any.bar.example.com=buzz:any:thing.example.org",
		},
		{
			name: "edgecase missing values",
			in:   "x in (foo,,baz),y,z notin ()",
			want: "any.x in (foo,,baz),any.y,any.z notin ()",
		},
		{
			name: "multi value edgecase",
			in:   "foo.example.com in (foo, any.bar, k8s:buzz, some.other,, end), k8s:bar in (a,b,c,  ,d,  e,),!any:test",
			want: "any.foo.example.com in (foo, any.bar, k8s:buzz, some.other,, end), k8s.bar in (a,b,c,  ,d,  e,),!any.test",
		},
		{
			name: "complex edgecase",
			in:   "a=b, foo:bar, !k8s:b, foo in  (a, ,   c, d), !any:buzz, c!= d.e, foo:bar.example.com=any.value, !any.other, k8s.example.com in (foo.bar, bar.buzz,  a)",
			want: "any.a=b, foo.bar, !k8s.b, any.foo in  (a, ,   c, d), !any.buzz, any.c!= d.e, foo.bar.example.com=any.value, !any.any.other, any.k8s.example.com in (foo.bar, bar.buzz,  a)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := translateSelector(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSelector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSelector() = %q, want %q", got, tt.want)
			}
		})
	}
}
