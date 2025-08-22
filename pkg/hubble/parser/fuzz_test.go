// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package parser

import (
	"log/slog"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
)

var (
	payloads = map[int]string{
		0: "PerfEvent",
		1: "AgentEvent",
		2: "LostEvent",
	}
)

func FuzzParserDecode(data []byte) int {
	p, err := New(slog.New(slog.DiscardHandler), nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return 0
	}

	f := fuzz.NewConsumer(data)
	payloadType, err := f.GetInt()
	if err != nil {
		return 0
	}

	mo := &observerTypes.MonitorEvent{}

	switch payloads[payloadType%len(payloads)] {
	case "PerfEvent":
		pe := &observerTypes.PerfEvent{}
		f.GenerateStruct(pe)
		mo.Payload = pe
	case "AgentEvent":
		ae := &observerTypes.AgentEvent{}
		f.GenerateStruct(ae)
		mo.Payload = ae
	case "LostEvent":
		le := &observerTypes.LostEvent{}
		f.GenerateStruct(le)
		mo.Payload = le
	}
	_, _ = p.Decode(mo)
	return 0
}
