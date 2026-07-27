// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/resiliency"
)

func TestErrorJoin(t *testing.T) {
	uu := map[string]struct {
		errs  []error
		total int
		e     string
	}{
		"none": {},
		"nils": {
			errs: []error{nil, nil},
		},
		"plain": {
			errs:  []error{errors.New("e1"), errors.New("e2"), errors.New("e3")},
			total: 3,
			e:     "test (3/3) failed\ne1\ne2\ne3",
		},
		"dups": {
			errs:  []error{errors.New("e1"), errors.New("e2"), errors.New("e1")},
			total: 3,
			e:     "test (2/3) failed\ne1\ne2",
		},
		"mix": {
			errs:  []error{errors.New("e1"), errors.New("e2"), errors.New("e1"), nil, errors.New("e2")},
			total: 5,
			e:     "test (2/5) failed\ne1\ne2",
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			es := resiliency.NewErrorSet("test", len(u.errs))
			es.Add(u.errs...)
			if es.Error() != nil {
				assert.Equal(t, u.e, errors.Join(es.Error()).Error())
			}
		})
	}
}

func TestErrorSetAdd(t *testing.T) {
	uu := map[string]struct {
		errs []error
		e    string
	}{
		"none": {},
		"nils": {
			errs: []error{nil, nil},
		},
		"plain": {
			errs: []error{errors.New("e1"), errors.New("e2"), errors.New("e3")},
			e:    "test (3/3) failed\ne1\ne2\ne3",
		},
		"dups": {
			errs: []error{errors.New("e1"), errors.New("e2"), errors.New("e1")},
			e:    "test (2/3) failed\ne1\ne2",
		},
		"mix": {
			errs: []error{errors.New("e1"), errors.New("e2"), errors.New("e1"), nil, errors.New("e2")},
			e:    "test (2/5) failed\ne1\ne2",
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			es := resiliency.NewErrorSet("test", len(u.errs))
			es.Add(u.errs...)
			if es.Error() != nil {
				assert.Equal(t, u.e, es.Error().Error())
			}
		})
	}
}
