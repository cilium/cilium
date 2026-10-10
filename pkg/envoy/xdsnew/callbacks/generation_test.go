// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
)

func TestGenerationComparisons(t *testing.T) {
	for _, test := range []struct {
		name       string
		generation Generation
		value      Generation
	}{
		{"initial", 0, 0},
		{"older", 42, 41},
		{"same", 42, 42},
		{"newer", 42, 43},
		{"not yet published", 0, 1},
		{"maximum", math.MaxUint64, math.MaxUint64},
		{"maximum revision", 42, math.MaxUint64},
	} {
		t.Run(test.name, func(t *testing.T) {
			revision, transaction := test.value.Revision(), test.value.TransactionID()
			require.Equal(t, test.value == 0, revision.IsZero())
			require.Equal(t, test.value == 0, transaction.IsZero())
			require.Equal(t, test.value, revision.revision)
			require.Equal(t, test.value, transaction.transaction)
			require.Equal(t, revision, transaction.InitialRevision())
			require.Equal(t, max(test.value, test.generation), test.generation.MaxRevision(revision))
			require.Equal(t, max(test.value, test.generation), test.generation.MaxTransaction(transaction))
		})
	}
}

func TestGenerationRolesRequireExplicitHelpers(t *testing.T) {
	generationType := reflect.TypeFor[Generation]()
	revisionType := reflect.TypeFor[Revision]()
	transactionType := reflect.TypeFor[TransactionID]()
	for _, roleType := range []reflect.Type{revisionType, transactionType} {
		t.Run(roleType.Name(), func(t *testing.T) {
			require.Equal(t, generationType.Size(), roleType.Size(), "wrappers must not enlarge cached entries or map keys")
			require.True(t, roleType.Comparable(), "same-role equality and map/set membership must remain available")
			require.False(t, generationType.ConvertibleTo(roleType), "construction must use the generation helper")
			require.False(t, roleType.ConvertibleTo(generationType), "external callers must use the generation helpers")
		})
	}
	// Identical struct layouts with identical field names would permit these
	// casts, bypassing the documented relationship between the two roles.
	require.False(t, revisionType.ConvertibleTo(transactionType))
	require.False(t, transactionType.ConvertibleTo(revisionType))
}

func TestGenerationInTransactions(t *testing.T) {
	for _, test := range []struct {
		name         string
		transactions set.Set[TransactionID]
		generation   Generation
		want         bool
	}{
		{"empty", set.Set[TransactionID]{}, 1, false},
		{"zero member", set.NewSet(TransactionID{}), 0, true},
		{"singleton match", set.NewSet(Generation(42).TransactionID()), 42, true},
		{"singleton miss", set.NewSet(Generation(42).TransactionID()), 43, false},
		{"multiple match", set.NewSet(Generation(41).TransactionID(), Generation(42).TransactionID(), Generation(43).TransactionID()), 42, true},
		{"multiple miss", set.NewSet(Generation(41).TransactionID(), Generation(42).TransactionID(), Generation(43).TransactionID()), 44, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.generation.inTransactions(test.transactions))
		})
	}
}
