// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type e struct {
	B int
}

func (e *e) Map() (map[string]any, error) {
	return map[string]any{
		"b": e.B,
	}, nil
}

type s struct {
	A int
	e

	ignored bool
}

func (s *s) Map() (map[string]any, error) {
	inner, err := s.e.Map()
	if err != nil {
		return nil, err
	}
	inner["a"] = s.A

	return inner, nil
}

type compl struct {
	C int
}

func (c *compl) Map() (map[string]any, error) {
	return map[string]any{
		"c": c.C,
	}, nil
}

type dup struct {
	Foo int
}

func (d *dup) Map() (map[string]any, error) {
	return map[string]any{
		"a": d.Foo,
	}, nil
}

func TestStructToMap(t *testing.T) {
	obj := s{1, e{2}, true}
	want := map[string]any{"a": 1, "b": 2}

	values, err := Map(&obj)
	require.NoError(t, err)
	assert.Equal(t, want, values)

	values, err = Map([]any{&obj})
	require.NoError(t, err)
	assert.Equal(t, want, values)

	values, err = Map([]any{&obj, &compl{3}})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": 1, "b": 2, "c": 3}, values)

	_, err = Map([]any{&obj, &dup{3}})
	require.ErrorIs(t, err, errDuplicateVariable)

	// Make sure nil interface doesn't panic.
	_, err = Map(nil)
	require.Error(t, err)

	// Make sure nil pointer doesn't panic.
	_, err = Map((*s)(nil))
	require.Error(t, err)
}
