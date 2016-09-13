//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package bpf

/*
#cgo CFLAGS: -I../../bpf/include
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <sys/resource.h>
*/

import "C"

import (
	"unsafe"
)

type MapType int

// This enumeration must be in sync with <linux/bpf.h>
const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
	MapTypeProgArray
	MapTypePerfEventArray
	MapTypePerCPUHash
	MapTypePerCPUArray
	MapTypeStackTrace
	MapTypeCgroupArray
)

type MapObj interface {
	GetPtr() unsafe.Pointer
}

type Map struct {
	fd         int
	path       string
	mapType    MapType
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	isOpen     bool
}

func NewMap(path string, mapType MapType, keySize int, valueSize int, maxEntries int) *Map {
	return &Map{
		path:       path,
		mapType:    mapType,
		keySize:    uint32(keySize),
		valueSize:  uint32(valueSize),
		maxEntries: uint32(maxEntries),
		isOpen:     false,
	}
}

func (m *Map) OpenOrCreate() (bool, error) {
	fd, isNew, err := OpenOrCreateMap(m.path, int(m.mapType), m.keySize, m.valueSize, m.maxEntries)
	if err != nil {
		return false, err
	}

	m.fd = fd
	m.isOpen = true

	return isNew, nil
}

func (m *Map) Open() error {
	fd, err := ObjGet(m.path)
	if err != nil {
		return err
	}

	m.fd = fd
	m.isOpen = true

	return nil
}

type DumpFunc func(key []byte, value []byte)

func (m *Map) Dump(cb DumpFunc) error {
	key := make([]byte, m.keySize)
	nextKey := make([]byte, m.keySize)
	value := make([]byte, m.valueSize)

	if !m.isOpen {
		if err := m.Open(); err != nil {
			return err
		}
	}

	for {
		err := GetNextKey(
			m.fd,
			unsafe.Pointer(&key[0]),
			unsafe.Pointer(&nextKey[0]),
		)

		if err != nil {
			break
		}

		err = LookupElement(
			m.fd,
			unsafe.Pointer(&nextKey[0]),
			unsafe.Pointer(&value[0]),
		)

		if err != nil {
			return err
		}

		cb(nextKey, value)
		copy(key, nextKey)
	}

	return nil
}

func (m *Map) Lookup(key MapObj, value unsafe.Pointer) error {
	if !m.isOpen {
		if err := m.Open(); err != nil {
			return err
		}
	}

	return LookupElement(m.fd, key.GetPtr(), value)
}

func (m *Map) Update(key MapObj, value unsafe.Pointer) error {
	if !m.isOpen {
		if err := m.Open(); err != nil {
			return err
		}
	}

	return UpdateElement(m.fd, key.GetPtr(), value, 0)
}

func (m *Map) Delete(key MapObj) error {
	if !m.isOpen {
		if err := m.Open(); err != nil {
			return err
		}
	}

	return DeleteElement(m.fd, key.GetPtr())
}
