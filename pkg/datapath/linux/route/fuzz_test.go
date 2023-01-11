// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"runtime"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/vishvananda/netns"
)

func FuzzRoutes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		r := Route{}
		ff := fuzz.NewConsumer(data)
		ff.GenerateStruct(&r)

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		currentNetNS, err = netns.Get()
		if err != nil {
			t.Skip()
		}

		testNetNS, err := netns.New() // creates netns, and sets it to current
		if err != nil {
			t.Skip()
		}
		defer func() {
			err := netns.Set(currentNetNS)
			if err != nil {
				t.Fatalf("%v\n", err)
			}
			err = testNetNS.Close()
			if err != nil {
				t.Fatalf("%v\n", err)
			}
		}()
		err := Upsert(r)
		if err != nil {
			t.Skip()
		}
		_, err = Lookup(r)
		if err != nil {
			t.Fatal("The route was added but could not be found")
		}
		err = Delete(r)
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
