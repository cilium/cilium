// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"log/slog"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func FuzzResolvePolicy(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		r := api.Rule{}
		err := ff.GenerateStruct(&r)
		if err != nil {
			return
		}
		r.EndpointSelector = endpointSelectorA // force the endpoint selector to one that will select, so we definitely evaluate policy
		err = r.Sanitize()
		if err != nil {
			return
		}

		logger := slog.New(slog.DiscardHandler)
		td := newTestData(f, logger).withIDs(ruleTestIDs)
		td.repo.mustAdd(r)
		sp, err := td.repo.resolvePolicyLocked(idA)
		if err != nil {
			return
		}
		sp.DistillPolicy(logger, &EndpointInfo{ID: uint64(idA.ID)}, nil)
	})
}

func FuzzDenyPreferredInsert(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		keys := emptyMapState(slog.New(slog.DiscardHandler))
		key := Key{}
		entry := NewMapStateEntry(types.AllowEntry())
		ff := fuzz.NewConsumer(data)
		ff.GenerateStruct(&key)
		ff.GenerateStruct(&entry)
		keys.insertWithChanges(types.Priority(0).ToPassPrecedence(), key, entry, allFeatures, ChangeState{})
	})
}

func FuzzAccumulateMapChange(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		adds := make([]identity.NumericIdentity, 0)
		ff.CreateSlice(&adds)
		deletes := make([]identity.NumericIdentity, 0)
		ff.CreateSlice(&deletes)
		port, err := ff.GetUint16()
		if err != nil {
			t.Skip()
		}
		protoUint8, err := ff.GetByte()
		if err != nil {
			t.Skip()
		}
		proto := u8proto.U8proto(protoUint8)
		dir := trafficdirection.Ingress
		redirect, err := ff.GetBool()
		if err != nil {
			t.Skip()
		}
		deny, err := ff.GetBool()
		if err != nil {
			t.Skip()
		}
		var proxyPort uint16
		if redirect {
			proxyPort = 1
		}
		key := KeyForDirection(dir).WithPortProto(proto, port)
		verdict := types.Allow
		if deny {
			verdict = types.Deny
		}
		value := newMapStateEntry(0, types.MaxPriority, NilRuleOrigin, proxyPort, 0, verdict, NoAuthRequirement)
		policyMaps := MapChanges{logger: slog.New(slog.DiscardHandler)}
		policyMaps.AccumulateMapChanges(0, 0, adds, deletes, []Key{key}, value)
		policyMaps.SyncMapChanges(types.MockSelectorSnapshot())
	})
}
