// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package exportercell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceBuilders(t *testing.T) {
	cases := []struct {
		name     string
		builders []*FlowLogExporterBuilder
		want     []*FlowLogExporterBuilder
		wantErr  bool
	}{
		{name: "nil"},
		{name: "empty", builders: []*FlowLogExporterBuilder{}},
		{
			name:     "one",
			builders: []*FlowLogExporterBuilder{{Name: "my-name"}},
			want:     []*FlowLogExporterBuilder{{Name: "my-name"}},
		},
		{
			name:     "one-empty-name",
			builders: []*FlowLogExporterBuilder{{Name: ""}},
			wantErr:  true,
		},
		{
			name:     "one-replaces",
			builders: []*FlowLogExporterBuilder{{Name: "my-name", Replaces: "not-found"}},
			want:     []*FlowLogExporterBuilder{{Name: "my-name", Replaces: "not-found"}},
		},
		{
			name:     "two",
			builders: []*FlowLogExporterBuilder{{Name: "one"}, {Name: "two"}},
			want:     []*FlowLogExporterBuilder{{Name: "one"}, {Name: "two"}},
		},
		{
			name:     "two-replaces",
			builders: []*FlowLogExporterBuilder{{Name: "one", Replaces: "two"}, {Name: "two"}},
			want:     []*FlowLogExporterBuilder{{Name: "one", Replaces: "two"}},
		},
		{
			name:     "two-replaces-not-found",
			builders: []*FlowLogExporterBuilder{{Name: "one", Replaces: "three"}, {Name: "two"}},
			want:     []*FlowLogExporterBuilder{{Name: "one", Replaces: "three"}, {Name: "two"}},
		},
		{
			name:     "two-replaces-self",
			builders: []*FlowLogExporterBuilder{{Name: "one", Replaces: "one"}, {Name: "two"}},
			want:     []*FlowLogExporterBuilder{{Name: "one", Replaces: "one"}, {Name: "two"}},
		},
		{
			name:     "two-one-empty-name",
			builders: []*FlowLogExporterBuilder{{Name: "one"}, {Name: ""}},
			wantErr:  true,
		},
		{
			name:     "two-duplicates",
			builders: []*FlowLogExporterBuilder{{Name: "one"}, {Name: "one"}},
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := replaceBuilders(tc.builders)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}
