// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Emitter tracks flow emitter information.
type Emitter struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

func (e Emitter) isEmpty() bool {
	return e.Name == "" && e.Version == ""
}

func (e Emitter) toProto() *flow.Emitter {
	if e.isEmpty() {
		return nil
	}

	return &flow.Emitter{
		Name:    e.Name,
		Version: e.Version,
	}
}

func protoToEmitter(e *flow.Emitter) Emitter {
	if e == nil {
		return Emitter{}
	}

	return Emitter{
		Name:    e.Name,
		Version: e.Version,
	}
}
