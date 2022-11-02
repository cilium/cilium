// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package format

import (
	"runtime"
	"testing"

	"github.com/cilium/cilium/pkg/monitor/payload"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

/*
This fuzzer invokes the garbage collector, because
fmt.Sprintf() seemingly will not free memory between
runs. The GC slows down the fuzzer significantly.
*/
func FuzzFormatEvent(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)
		pl := &payload.Payload{}
		err := f.GenerateStruct(pl)
		if err != nil {
			return
		}

		// Invalid pl.Data. Leave here to avoid
		// invoking the GC.
		if len(pl.Data) == 0 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
			}
			runtime.GC()
		}()

		mf := NewMonitorFormatter(0, nil)

		mf.FormatEvent(pl)
		return
	})
}
