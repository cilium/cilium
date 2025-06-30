// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
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

func (t *RemoteTable[Obj]) query(ctx context.Context, lowerBound bool, q Query[Obj]) (seq iter.Seq2[Obj, Revision], errChan <-chan error) {
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
	return remoteGetSeq[Obj](json.NewDecoder(resp.Body), errChanSend), errChan
}

func (t *RemoteTable[Obj]) Get(ctx context.Context, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan error) {
	return t.query(ctx, false, q)
}

func (t *RemoteTable[Obj]) LowerBound(ctx context.Context, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan error) {
	return t.query(ctx, true, q)
}

// responseObject is a typed counterpart of [queryResponseObject]
type responseObject[Obj any] struct {
	Rev uint64 `json:"rev"`
	Obj Obj    `json:"obj"`
	Err string `json:"err,omitempty"`
}

func remoteGetSeq[Obj any](dec *json.Decoder, errChan chan error) iter.Seq2[Obj, Revision] {
	return func(yield func(Obj, Revision) bool) {
		for {
			var resp responseObject[Obj]
			err := dec.Decode(&resp)
			errString := ""
			if err != nil {
				if errors.Is(err, io.EOF) {
					close(errChan)
					break
				}
				errString = "Decode error: " + err.Error()
			} else {
				errString = resp.Err
			}
			if errString != "" {
				errChan <- errors.New(errString)
				break
			}
			if !yield(resp.Obj, resp.Rev) {
				break
			}
		}
	}
}

func (t *RemoteTable[Obj]) Changes(ctx context.Context) (seq iter.Seq2[Change[Obj], Revision], errChan <-chan error) {
	// Use a channel to return errors so we can use the same Iterator[Obj] interface as StateDB does.
	errChanSend := make(chan error, 1)
	errChan = errChanSend

	url := t.base.JoinPath("/changes", t.tableName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		errChanSend <- err
		close(errChanSend)
		return
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		errChanSend <- err
		close(errChanSend)
		return
	}
	return remoteChangeSeq[Obj](json.NewDecoder(resp.Body), errChanSend), errChan
}

func remoteChangeSeq[Obj any](dec *json.Decoder, errChan chan error) iter.Seq2[Change[Obj], Revision] {
	return func(yield func(Change[Obj], Revision) bool) {
		defer close(errChan)
		for {
			var change Change[Obj]
			err := dec.Decode(&change)
			if err == nil && change.Revision == 0 {
				// Keep-alive message, skip it.
				continue
			}

			if err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- fmt.Errorf("decode error: %w", err)
				}
				return
			}

			if !yield(change, change.Revision) {
				return
			}
		}
	}
}
