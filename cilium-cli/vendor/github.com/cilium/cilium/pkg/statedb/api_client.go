// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"os"

	"github.com/cilium/cilium/api/v1/client/statedb"
	"github.com/cilium/cilium/pkg/client"
)

// NewRemoteTable creates a new handle for querying a remote StateDB table over the REST API.
// Example usage:
//
//	var client *client.Client
//
//	devices := statedb.NewRemoteTable[*tables.Device](client, "devices")
//
//	// Get all devices ordered by name.
//	iter, errs := devices.LowerBound(ctx, tables.DeviceByName(""))
//	for device, revision, ok := iter.Next(); ok; device, revision, ok = iter.Next() { ... }
//
//	// Get device by name.
//	iter, errs := devices.Get(ctx, tables.DeviceByName("eth0"))
//	if dev, revision, ok := iter.Next(); ok { ... }
//
//	// Get devices in revision order, e.g. oldest changed devices first.
//	iter, errs = devices.LowerBound(ctx, statedb.ByRevision(0))
func NewRemoteTable[Obj any](client *client.Client, table TableName) *RemoteTable[Obj] {
	return &RemoteTable[Obj]{tableName: table, client: client}
}

type RemoteTable[Obj any] struct {
	tableName TableName
	client    *client.Client
}

func (t *RemoteTable[Obj]) query(ctx context.Context, lowerBound bool, q Query[Obj]) (Iterator[Obj], <-chan error) {
	// Unconventionally using a channel for errors since we will run the actual request in the
	// background to feed the iterator.
	errChan := make(chan error, 1)

	r, w, err := os.Pipe()
	if err != nil {
		errChan <- err
		close(errChan)
		return nil, errChan
	}

	// Fork a goroutine to feed the pipe from which the gob-encoded stream of objects
	// is decoded from.
	go func() {
		defer close(errChan)
		defer w.Close()
		key := base64.StdEncoding.EncodeToString(q.key)
		_, err := t.client.Statedb.GetStatedbQueryTable(
			&statedb.GetStatedbQueryTableParams{
				Index:      q.index,
				Key:        key,
				Lowerbound: lowerBound,
				Table:      t.tableName,

				Context: ctx,
			},
			w,
		)
		errChan <- err
	}()

	return &remoteGetIterator[Obj]{gob.NewDecoder(r)}, errChan
}
func (t *RemoteTable[Obj]) Get(ctx context.Context, q Query[Obj]) (Iterator[Obj], <-chan error) {
	return t.query(ctx, false, q)
}

func (t *RemoteTable[Obj]) LowerBound(ctx context.Context, q Query[Obj]) (Iterator[Obj], <-chan error) {
	return t.query(ctx, true, q)
}

type remoteGetIterator[Obj any] struct {
	decoder *gob.Decoder
}

func (it *remoteGetIterator[Obj]) Next() (obj Obj, revision Revision, ok bool) {
	err := it.decoder.Decode(&revision)
	if err != nil {
		return
	}
	err = it.decoder.Decode(&obj)
	if err != nil {
		return
	}
	ok = true
	return
}
