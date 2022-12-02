// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux/route"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"gopkg.in/check.v1"
)

const (
	privilegedEnv            = "PRIVILEGED_TESTS"
	gatewayAPIConformanceEnv = "GATEWAY_API_CONFORMANCE_TESTS"
)

func PrivilegedTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(privilegedEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", privilegedEnv))
	}
}

func PrivilegedCheck(c *check.C) {
	if os.Getenv(privilegedEnv) == "" {
		c.Skip(fmt.Sprintf("Set %s to run this test", privilegedEnv))
	}
}

func GatewayAPIConformanceTest(tb testing.TB) {
	tb.Helper()

	if os.Getenv(gatewayAPIConformanceEnv) == "" {
		tb.Skip(fmt.Sprintf("Set %s to run this test", gatewayAPIConformanceEnv))
	}
}

func FuzzRoutes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		r := route.Route{}
		ff := fuzz.NewConsumer(data)
		ff.GenerateStruct(&r)
		err := route.Upsert(r)
		if err != nil {
			t.Skip()
		}
		_, err = route.Lookup(r)
		if err != nil {
			t.Fatal("The route was added but could not be found")
		}
		err = route.Delete(r)
		if err != nil {
			t.Fatal("The route was added and found but could not be deleted")
		}
	})
}

func FuzzListRules(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, family int) {
		ff := fuzz.NewConsumer(data)
		filter := &route.Rule{}
		ff.GenerateStruct(filter)
		_, _ = route.ListRules(family, filter)
	})
}
