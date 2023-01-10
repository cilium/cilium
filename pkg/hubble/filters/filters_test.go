// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestApply(t *testing.T) {
	ffyes := FilterFuncs{func(_ *v1.Event) bool {
		return true
	}}
	ffno := FilterFuncs{func(_ *v1.Event) bool {
		return false
	}}

	type args struct {
		whitelist FilterFuncs
		blacklist FilterFuncs
		ev        *v1.Event
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{args: args{whitelist: ffyes}, want: true},
		{args: args{whitelist: ffno}, want: false},
		{args: args{blacklist: ffno}, want: true},
		{args: args{blacklist: ffyes}, want: false},
		{args: args{whitelist: ffyes, blacklist: ffyes}, want: false},
		{args: args{whitelist: ffyes, blacklist: ffno}, want: true},
		{args: args{whitelist: ffno, blacklist: ffyes}, want: false},
		{args: args{whitelist: ffno, blacklist: ffno}, want: false},
		{args: args{}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Apply(tt.args.whitelist, tt.args.blacklist, tt.args.ev); got != tt.want {
				t.Errorf("Apply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	fyes := func(_ *v1.Event) bool {
		return true
	}
	fno := func(_ *v1.Event) bool {
		return false
	}
	fs := FilterFuncs{fyes, fno}
	assert.False(t, fs.MatchAll(nil))
	assert.True(t, fs.MatchOne(nil))
	assert.False(t, fs.MatchNone(nil))

	// When no filter is specified, MatchAll(), MatchOne() and MatchNone() must
	// all return true
	fs = FilterFuncs{}
	assert.True(t, fs.MatchAll(nil))
	assert.True(t, fs.MatchOne(nil))
	assert.True(t, fs.MatchNone(nil))
}

type testFilterTrue struct{}

func (t *testFilterTrue) OnBuildFilter(_ context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	return []FilterFunc{func(ev *v1.Event) bool { return true }}, nil
}

type testFilterFalse struct{}

func (t *testFilterFalse) OnBuildFilter(_ context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	return []FilterFunc{func(ev *v1.Event) bool { return false }}, nil
}

func TestOnBuildFilter(t *testing.T) {
	fl, err := BuildFilterList(context.Background(),
		[]*flowpb.FlowFilter{{SourceIdentity: []uint32{1, 2, 3}}}, // true
		[]OnBuildFilter{&testFilterTrue{}})                        // true
	assert.NoError(t, err)
	assert.Equal(t, true, fl.MatchAll(&v1.Event{Event: &flowpb.Flow{
		Source: &flowpb.Endpoint{Identity: 3},
	}}))

	fl, err = BuildFilterList(context.Background(),
		[]*flowpb.FlowFilter{{SourceIdentity: []uint32{1, 2, 3}}}, // true
		[]OnBuildFilter{&testFilterFalse{}})                       // false
	assert.NoError(t, err)
	assert.Equal(t, false, fl.MatchAll(&v1.Event{Event: &flowpb.Flow{
		Source: &flowpb.Endpoint{Identity: 3},
	}}))

	fl, err = BuildFilterList(context.Background(),
		[]*flowpb.FlowFilter{{SourceIdentity: []uint32{1, 2, 3}}}, // true
		[]OnBuildFilter{
			&testFilterFalse{}, // false
			&testFilterTrue{}}) // true
	assert.NoError(t, err)
	assert.Equal(t, false, fl.MatchAll(&v1.Event{Event: &flowpb.Flow{
		Source: &flowpb.Endpoint{Identity: 3},
	}}))
}
