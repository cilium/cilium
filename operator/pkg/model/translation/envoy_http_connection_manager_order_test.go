// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestHTTPFiltersKeepAuthorizationBeforeInference(t *testing.T) {
	epp := &model.EndpointPicker{Namespace: "default", Name: "picker", Port: 9002}
	auth := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Namespace: "default", Name: "auth", Port: &model.BackendPort{Port: 9000}},
		Protocol: model.ExternalAuthProtocolGRPC,
	}
	processor := model.ExtensionRefFilter{Name: "envoy.filters.http.ext_proc/default/processor", TypeURL: model.ExtProcExternalProcessorTypeURL}

	for _, tc := range []struct {
		name    string
		filters []model.ExtensionRefFilter
	}{
		{name: "without ExtensionRefs"},
		{name: "with ExtensionRef", filters: []model.ExtensionRefFilter{processor}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{
				Backends:            []model.Backend{{EndpointPicker: epp}},
				ExternalAuth:        auth,
				ExtensionRefFilters: tc.filters,
			}}}}}
			var names []string
			for _, filter := range (&cecTranslator{}).getHTTPConnectionManagerHttpFilters(m) {
				names = append(names, filter.Name)
			}
			authIndex := slices.Index(names, ExtAuthzFilterName(extAuthzFilterKey(auth)))
			eppIndex := slices.Index(names, ExtProcFilterName(getEPPClusterName(epp)))
			require.NotEqual(t, -1, authIndex)
			require.NotEqual(t, -1, eppIndex)
			require.Less(t, authIndex, eppIndex)
			if len(tc.filters) > 0 {
				processorIndex := slices.Index(names, processor.Name)
				require.NotEqual(t, -1, processorIndex)
				require.Less(t, processorIndex, authIndex)
			}
		})
	}
}
