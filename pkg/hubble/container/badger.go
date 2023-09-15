// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package container

import (
	"errors"
	"io"
	"os"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

var (
	_ EventReadWriter = (*BadgerDB)(nil)
	_ EventIterator   = (*badgerDBIterator)(nil)
)

const dbDirectory = "/var/run/cilium/hubble/badger"

type BadgerDB struct {
	db       *badger.DB
	eventTTL time.Duration
}

func NewBadgerDB(onDisk bool, eventTTL time.Duration) (*BadgerDB, error) {
	if eventTTL < time.Second {
		return nil, errors.New("invalid eventTTL, must be at least 1 second")
	}
	var opts badger.Options
	if onDisk {
		err := os.MkdirAll(dbDirectory, 0600)
		if err != nil {
			return nil, err
		}
		opts = badger.DefaultOptions(dbDirectory)
	} else {
		opts = badger.DefaultOptions("").WithInMemory(true)
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerDB{db: db, eventTTL: eventTTL}, nil
}

func (eb *BadgerDB) Write(ev *v1.Event) error {
	return eb.db.Update(func(txn *badger.Txn) error {
		key := []byte(ev.Timestamp.AsTime().UTC().UTC().Format(time.RFC3339Nano))
		// TODO: support more than flows
		if flow := ev.GetFlow(); flow != nil {
			val, err := proto.Marshal(flow)
			if err != nil {
				return err
			}
			entry := badger.NewEntry(key, val).WithTTL(eb.eventTTL)
			return txn.SetEntry(entry)
		}
		return nil
	})
}

func (eb *BadgerDB) Iterator() EventIterator {
	txn := eb.db.NewTransaction(false)
	opts := badger.DefaultIteratorOptions
	iterator := txn.NewIterator(opts)
	iterator.Rewind()
	return &badgerDBIterator{txn: txn, iterator: iterator}
}

type badgerDBIterator struct {
	txn      *badger.Txn
	iterator *badger.Iterator
}

func (ebi *badgerDBIterator) Next() (*v1.Event, error) {
	if !ebi.iterator.Valid() {
		return nil, io.EOF
	}
	defer ebi.iterator.Next()

	item := ebi.iterator.Item()
	key := item.Key()
	t, err := time.Parse(time.RFC3339Nano, string(key))
	if err != nil {
		return nil, err
	}
	ts := timestamppb.New(t)

	var f flowpb.Flow
	err = item.Value(func(v []byte) error {
		return proto.Unmarshal(v, &f)
	})
	if err != nil {
		return nil, err
	}
	return &v1.Event{
		Timestamp: ts,
		Event:     &f,
	}, nil
}

func (it *badgerDBIterator) Close() error {
	return it.txn.Commit()
}
