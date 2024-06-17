// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// NewRemoteTable creates a new handle for querying a remote StateDB table over the HTTP.
// Example usage:
//
//	devices := statedb.NewRemoteTable[*tables.Device](url.Parse("http://localhost:8080/db"), "devices")
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
func NewRemoteTable[Obj any](base *url.URL, table TableName) *RemoteTable[Obj] {
	return &RemoteTable[Obj]{base: base, tableName: table}
}

type RemoteTable[Obj any] struct {
	client    http.Client
	base      *url.URL
	tableName TableName
}

func (t *RemoteTable[Obj]) SetTransport(tr *http.Transport) {
	t.client.Transport = tr
}

func (t *RemoteTable[Obj]) query(ctx context.Context, lowerBound bool, q Query[Obj]) (iter Iterator[Obj], errChan <-chan error) {
	// Use a channel to return errors so we can use the same Iterator[Obj] interface as StateDB does.
	errChanSend := make(chan error, 1)
	errChan = errChanSend

	key := base64.StdEncoding.EncodeToString(q.key)
	queryReq := QueryRequest{
		Key:        key,
		Table:      t.tableName,
		Index:      q.index,
		LowerBound: lowerBound,
	}
	bs, err := json.Marshal(&queryReq)
	if err != nil {
		errChanSend <- err
		return
	}

	url := t.base.JoinPath("/query")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), bytes.NewBuffer(bs))
	if err != nil {
		errChanSend <- err
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		errChanSend <- err
		return
	}
	return &remoteGetIterator[Obj]{json.NewDecoder(resp.Body), errChanSend}, errChan
}
func (t *RemoteTable[Obj]) Get(ctx context.Context, q Query[Obj]) (Iterator[Obj], <-chan error) {
	return t.query(ctx, false, q)
}

func (t *RemoteTable[Obj]) LowerBound(ctx context.Context, q Query[Obj]) (Iterator[Obj], <-chan error) {
	return t.query(ctx, true, q)
}

type remoteGetIterator[Obj any] struct {
	decoder *json.Decoder
	errChan chan error
}

// responseObject is a typed counterpart of [queryResponseObject]
type responseObject[Obj any] struct {
	Rev uint64 `json:"rev"`
	Obj Obj    `json:"obj"`
	Err string `json:"err,omitempty"`
}

func (it *remoteGetIterator[Obj]) Next() (obj Obj, revision Revision, ok bool) {
	if it.decoder == nil {
		return
	}

	var resp responseObject[Obj]
	err := it.decoder.Decode(&resp)
	errString := ""
	if err != nil {
		if errors.Is(err, io.EOF) {
			close(it.errChan)
			return
		}
		errString = "Decode error: " + err.Error()
	} else {
		errString = resp.Err
	}
	if errString != "" {
		it.decoder = nil
		it.errChan <- errors.New(errString)
		return
	}

	obj = resp.Obj
	revision = resp.Rev
	ok = true
	return
}
