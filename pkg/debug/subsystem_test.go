// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package debug

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type debugObj struct{}

func (d *debugObj) DebugStatus() string {
	return "test3"
}

func TestSubsystem(t *testing.T) {
	sf := newStatusFunctions()
	require.Equal(t, StatusMap{}, sf.collectStatus())

	sf = newStatusFunctions()
	sf.register("foo", func() string { return "test1" })
	require.Equal(t, StatusMap{
		"foo": "test1",
	}, sf.collectStatus())

	sf.register("bar", func() string { return "test2" })
	require.Equal(t, StatusMap{
		"foo": "test1",
		"bar": "test2",
	}, sf.collectStatus())

	sf.register("bar", func() string { return "test2" })
	require.Equal(t, StatusMap{
		"foo": "test1",
		"bar": "test2",
	}, sf.collectStatus())

	sf.registerStatusObject("baz", &debugObj{})
	require.Equal(t, StatusMap{
		"foo": "test1",
		"bar": "test2",
		"baz": "test3",
	}, sf.collectStatus())
}
