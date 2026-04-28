// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crap

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
)

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	assert.NoError(t, err)
}

func TestNewKey(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")

	key := NewKey(addr)

	assert.True(t, key.Match(addr))
	assert.Equal(t, "10.0.0.1", key.String())
}

func TestNewVal(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.10")

	val := NewVal(addr)

	assert.True(t, (&val).Match(addr))
	assert.Equal(t, "pod_ip=192.168.1.10", (&val).String())
}

func TestCrapKeyNew(t *testing.T) {
	key := &CrapKey{}
	assert.IsType(t, &CrapKey{}, key.New())
}

func TestCrapValNew(t *testing.T) {
	val := &CrapVal{}
	assert.IsType(t, &CrapVal{}, val.New())
}

func TestMatchRejectsOtherAddress(t *testing.T) {
	key := NewKey(netip.MustParseAddr("10.0.0.1"))
	val := NewVal(netip.MustParseAddr("10.0.0.2"))

	assert.False(t, key.Match(netip.MustParseAddr("10.0.0.3")))
	assert.False(t, (&val).Match(netip.MustParseAddr("10.0.0.4")))
}
