// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"fmt"

	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/k8s/testutils"
)

// EventStreamFromFiles returns an observable stream of events created from decoding the
// given slice of files and emitted as Upserts.
func EventStreamFromFiles[T runtime.Object](paths []string) func() stream.Observable[Event[T]] {
	src := make(chan Event[T], 1)
	src <- Event[T]{
		Kind: Sync,
		Done: func(error) {},
	}
	go func() {
		for _, path := range paths {
			rawObj, err := testutils.DecodeFile(path)
			if err != nil {
				panic(err)
			}
			obj := rawObj.(T)
			src <- Event[T]{
				Kind:   Upsert,
				Key:    NewKey(obj),
				Object: obj,
				Done: func(err error) {
					if err != nil {
						panic(fmt.Sprintf("Event.Done called with error: %s", err))
					}
				},
			}
		}
	}()
	return func() stream.Observable[Event[T]] { return stream.FromChannel(src) }
}
