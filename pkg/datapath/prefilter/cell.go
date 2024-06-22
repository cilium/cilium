// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// Cell provides prefilter, a means of configuring XDP pre-filters for DDoS-mitigation.
var Cell = cell.Module(
	"prefilter",
	"Provides a means of configuring XDP pre-filters for DDoS-mitigation",

	cell.Provide(newPreFilter),
	cell.Provide(newPrefilterApiHandler),
)

type prefilterApiHandlerOut struct {
	cell.Out

	GetPrefilterHandler    prefilter.GetPrefilterHandler
	PatchPrefilterHandler  prefilter.PatchPrefilterHandler
	DeletePrefilterHandler prefilter.DeletePrefilterHandler
}

func newPrefilterApiHandler(prefilter datapath.PreFilter) prefilterApiHandlerOut {
	return prefilterApiHandlerOut{
		GetPrefilterHandler:    &getPrefilterHandler{preFilter: prefilter},
		PatchPrefilterHandler:  &patchPrefilterHandler{preFilter: prefilter},
		DeletePrefilterHandler: &deletePrefilterHandler{preFilter: prefilter},
	}
}
