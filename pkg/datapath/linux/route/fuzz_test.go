// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers"
)

func FuzzRoutes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		route := Route{}
		ff := fuzz.NewConsumer(data)
		ff.GenerateStruct(&route)
		err := Upsert(route)
		if err != nil {
			t.Skip()
		}
		_, err = Lookup(route)
		if err != nil {
			t.Fatal("The route was added but could not be found")
		}
		err = Delete(route)
		if err != nil {
			t.Fatal("The route was added and found but could not be deleted")
		}
	})
}

func FuzzListRules(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, family int) {
		ff := fuzz.NewConsumer(data)
		filter := &Rule{}
		ff.GenerateStruct(filter)
		_, _ = ListRules(family, filter)
	})
}
