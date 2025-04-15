// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

const (
	// BGPReconcileErrCountPerInstance is number of errors stored per instance in statedb.
	BGPReconcileErrCountPerInstance = 5
)

type BGPReconcileError struct {
	Instance string
	ErrorID  int
	Error    string
}

func (re *BGPReconcileError) DeepCopy() *BGPReconcileError {
	return &BGPReconcileError{
		Instance: re.Instance,
		ErrorID:  re.ErrorID,
		Error:    re.Error,
	}
}

func (re *BGPReconcileError) String() string {
	return fmt.Sprintf("BGPReconcileError{Instance: %s, ErrorID: %d, Error: %s}", re.Instance, re.ErrorID, re.Error)
}

func (re *BGPReconcileError) TableHeader() []string {
	return []string{
		"Instance",
		"ErrorID",
		"Error",
	}
}

func (re *BGPReconcileError) TableRow() []string {
	return []string{
		re.Instance,
		fmt.Sprintf("%d", re.ErrorID),
		re.Error,
	}
}

type BGPReconcileErrorKey struct {
	Instance string
	ErrorID  int
}

func (k BGPReconcileErrorKey) Key() index.Key {
	return index.String(fmt.Sprintf("%s-%d", k.Instance, k.ErrorID))
}

var (
	BGPReconcileErrorIndex = statedb.Index[*BGPReconcileError, BGPReconcileErrorKey]{
		Name: "key",
		FromObject: func(obj *BGPReconcileError) index.KeySet {
			return index.NewKeySet(
				BGPReconcileErrorKey{
					Instance: obj.Instance,
					ErrorID:  obj.ErrorID,
				}.Key(),
			)
		},
		FromKey: BGPReconcileErrorKey.Key,
		Unique:  true,
	}
	BGPReconcileErrorInstance = statedb.Index[*BGPReconcileError, string]{
		Name: "Instance",
		FromObject: func(obj *BGPReconcileError) index.KeySet {
			return index.NewKeySet(index.String(obj.Instance))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
)

func NewBGPReconcileErrorTable() (statedb.RWTable[*BGPReconcileError], error) {
	return statedb.NewTable(
		"bgp-reconcile-errors",
		BGPReconcileErrorIndex,
		BGPReconcileErrorInstance,
	)
}
