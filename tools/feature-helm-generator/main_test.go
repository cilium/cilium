// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_genRSTTable(t *testing.T) {
	type args struct {
		metrics    []Metric
		prefix     string
		separators []string
	}
	tests := []struct {
		name  string
		args  args
		wantO string
	}{
		{
			name: "",
			args: args{
				metrics: []Metric{
					{
						Name:        "cilium_feature_group_0_foo_no_labels",
						Description: "This is a cilium feature without labels",
						Type:        "gauge",
					},
					{
						Name: "cilium_feature_group_1_with_labels",
						Labels: map[string]map[string]struct{}{
							"mode": {
								"value-1": {},
								"value-2": {},
								"value-3": {},
							},
						},
						Description: "This is a cilium feature with labels",
						Type:        "counter",
					},
					{
						Name: "cilium_feature_group_2_with_labels",
						Labels: map[string]map[string]struct{}{
							"mode": {
								"value-1": {},
							},
						},
						Description: "This is a cilium feature with labels",
						Type:        "counter",
					},
				},
				prefix:     "cilium_feature",
				separators: []string{"group_1"},
			},
			wantO: `.. _cilium-feature-group-1:

` + "``group_1``" + `
~~~~~~~~~~~
.. list-table::
  :header-rows: 1

  * - Name
    - Labels
    - Possible Label Values
    - Description
    - Type
  * - ` + "``with_labels``" + `
    - ` + "``mode``" + `
    - ` + "``value-1``" + `
    - This is a cilium feature with labels
    - counter
  * -
    -
    - ` + "``value-2``" + `
    -
    -
  * -
    -
    - ` + "``value-3``" + `
    -
    -

.. _misc:

` + "misc" + `
~~~~
.. list-table::
  :header-rows: 1

  * - Name
    - Labels
    - Possible Label Values
    - Description
    - Type
  * - ` + "``group_0_foo_no_labels``" + `
    - *None*
    - *None*
    - This is a cilium feature without labels
    - gauge
  * - ` + "``group_2_with_labels``" + `
    - ` + "``mode``" + `
    - ` + "``value-1``" + `
    - This is a cilium feature with labels
    - counter

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &bytes.Buffer{}
			genRSTTable(o, tt.args.metrics, tt.args.prefix, tt.args.separators)
			assert.Equal(t, tt.wantO, o.String())
		})
	}
}

func Test_parseMetricsFromProm(t *testing.T) {
	type args struct {
		promFile io.Reader
	}
	tests := []struct {
		name string
		args args
		want []Metric
	}{
		{
			name: "",
			args: args{
				promFile: strings.NewReader(`# HELP cilium_feature_controlplane_cilium_endpoint_slices_enabled Cilium Endpoint Slices enabled on the agent
# TYPE cilium_feature_controlplane_cilium_endpoint_slices_enabled gauge
cilium_feature_controlplane_cilium_endpoint_slices_enabled 0
# HELP cilium_feature_controlplane_identity_allocation Identity Allocation mode enabled on the agent
# TYPE cilium_feature_controlplane_identity_allocation gauge
cilium_feature_controlplane_identity_allocation{mode="crd"} 1
cilium_feature_controlplane_identity_allocation{mode="doublewrite-readcrd"} 0
cilium_feature_controlplane_identity_allocation{mode="doublewrite-readkvstore"} 0
cilium_feature_controlplane_identity_allocation{mode="kvstore"} 0`),
			},
			want: []Metric{
				{
					Name:        "cilium_feature_controlplane_cilium_endpoint_slices_enabled",
					Description: "Cilium Endpoint Slices enabled on the agent",
					Labels:      map[string]map[string]struct{}{},
					Type:        "gauge",
				},
				{
					Name:        "cilium_feature_controlplane_identity_allocation",
					Description: "Identity Allocation mode enabled on the agent",
					Labels: map[string]map[string]struct{}{
						"mode": {
							`"crd"`:                     {},
							`"doublewrite-readcrd"`:     {},
							`"doublewrite-readkvstore"`: {},
							`"kvstore"`:                 {},
						},
					},
					Type: "gauge",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parseMetricsFromProm(tt.args.promFile), "parseMetricsFromProm(%v)", tt.args.promFile)
		})
	}
}
