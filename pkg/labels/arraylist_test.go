// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLabelArrayListEquals(t *testing.T) {
	list1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list2 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list3 := LabelArrayList{
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list4 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list5 := LabelArrayList(nil)
	list6 := LabelArrayList{}

	require.Equal(t, true, list1.Equals(list1))
	require.Equal(t, true, list1.Equals(list2))
	require.Equal(t, false, list1.Equals(list3))
	require.Equal(t, false, list1.Equals(list4))
	require.Equal(t, false, list1.Equals(list5))
	require.Equal(t, false, list1.Equals(list6))

	require.Equal(t, true, list2.Equals(list1))
	require.Equal(t, true, list2.Equals(list2))
	require.Equal(t, false, list2.Equals(list3))
	require.Equal(t, false, list2.Equals(list4))
	require.Equal(t, false, list2.Equals(list5))
	require.Equal(t, false, list2.Equals(list6))

	require.Equal(t, false, list3.Equals(list1))
	require.Equal(t, false, list3.Equals(list2))
	require.Equal(t, true, list3.Equals(list3))
	require.Equal(t, false, list3.Equals(list4))
	require.Equal(t, false, list3.Equals(list5))
	require.Equal(t, false, list3.Equals(list6))

	require.Equal(t, false, list4.Equals(list1))
	require.Equal(t, false, list4.Equals(list2))
	require.Equal(t, false, list4.Equals(list3))
	require.Equal(t, true, list4.Equals(list4))
	require.Equal(t, false, list4.Equals(list5))
	require.Equal(t, false, list4.Equals(list6))

	require.Equal(t, false, list5.Equals(list1))
	require.Equal(t, false, list5.Equals(list2))
	require.Equal(t, false, list5.Equals(list3))
	require.Equal(t, false, list5.Equals(list4))
	require.Equal(t, true, list5.Equals(list5))
	require.Equal(t, true, list5.Equals(list6))

	require.Equal(t, false, list6.Equals(list1))
	require.Equal(t, false, list6.Equals(list2))
	require.Equal(t, false, list6.Equals(list3))
	require.Equal(t, false, list6.Equals(list4))
	require.Equal(t, true, list6.Equals(list5))
	require.Equal(t, true, list6.Equals(list6))
}

func TestLabelArrayListSort(t *testing.T) {
	require.EqualValues(t, LabelArrayList(nil), LabelArrayList(nil).Sort())
	require.EqualValues(t, LabelArrayList{}, LabelArrayList{}.Sort())

	list1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
			NewLabel("xyz", "", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		nil,
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	expected1 := LabelArrayList{
		nil,
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
			NewLabel("xyz", "", LabelSourceAny),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}

	require.EqualValues(t, expected1, list1.Sort())

	list2 := LabelArrayList{
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		{
			NewLabel("aaa", "", LabelSourceAny),
		},
	}
	expected2 := LabelArrayList{
		{
			NewLabel("aaa", "", LabelSourceAny),
		},
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
	}
	require.EqualValues(t, expected2, list2.Sort())
}

func TestLabelArrayListMergeSorted(t *testing.T) {
	list1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list2 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list3 := LabelArrayList{
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list4 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list5 := LabelArrayList(nil)
	list6 := LabelArrayList{}
	list7 := LabelArrayList{
		{
			NewLabel("env", "prod", LabelSourceAny),
			NewLabel("user", "alice", LabelSourceContainer),
		},
	}

	expected1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}

	cases := []struct {
		name     string
		a, b     LabelArrayList
		expected LabelArrayList
	}{
		{name: "same list", a: list1, b: list1, expected: expected1},
		{name: "equal lists", a: list1, b: list2, expected: expected1},
		{name: "unsorted equal lists", a: list1, b: list3, expected: expected1},
		{name: "list b contained in list a", a: list1, b: list4, expected: expected1},
		{name: "list a contained in list b", a: list4, b: list1, expected: expected1},
		{name: "nil label arrays", a: list1, b: list5, expected: list1},
		{name: "empty label array lists", a: list1, b: list6, expected: list1},
		{name: "two different lists", a: list1, b: list7, expected: LabelArrayList{
			{
				NewLabel("env", "devel", LabelSourceAny),
				NewLabel("user", "bob", LabelSourceContainer),
			},
			{
				NewLabel("env", "prod", LabelSourceAny),
				NewLabel("user", "alice", LabelSourceContainer),
			},
			{
				NewLabel("foo", "bar", LabelSourceAny),
			},
		}},
	}

	for _, tc := range cases {
		// Copy to avoid polluting lists for the next cases.
		a := tc.a.DeepCopy()
		b := tc.b.DeepCopy()
		a.Merge(b...)
		require.EqualValues(t, tc.expected, a, tc.name)
		require.EqualValues(t, a.Sort(), a, tc.name+" returned unsorted result")

		a = tc.a.DeepCopy().Sort()
		b = tc.b.DeepCopy().Sort()
		a.MergeSorted(b)
		require.EqualValues(t, tc.expected, a, tc.name+" MergeSorted")
		require.EqualValues(t, a.Sort(), a, tc.name+" MergeSorted returned unsorted result")
	}
}
