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

	require.True(t, list1.Equals(list1))
	require.True(t, list1.Equals(list2))
	require.False(t, list1.Equals(list3))
	require.False(t, list1.Equals(list4))
	require.False(t, list1.Equals(list5))
	require.False(t, list1.Equals(list6))

	require.True(t, list2.Equals(list1))
	require.True(t, list2.Equals(list2))
	require.False(t, list2.Equals(list3))
	require.False(t, list2.Equals(list4))
	require.False(t, list2.Equals(list5))
	require.False(t, list2.Equals(list6))

	require.False(t, list3.Equals(list1))
	require.False(t, list3.Equals(list2))
	require.True(t, list3.Equals(list3))
	require.False(t, list3.Equals(list4))
	require.False(t, list3.Equals(list5))
	require.False(t, list3.Equals(list6))

	require.False(t, list4.Equals(list1))
	require.False(t, list4.Equals(list2))
	require.False(t, list4.Equals(list3))
	require.True(t, list4.Equals(list4))
	require.False(t, list4.Equals(list5))
	require.False(t, list4.Equals(list6))

	require.False(t, list5.Equals(list1))
	require.False(t, list5.Equals(list2))
	require.False(t, list5.Equals(list3))
	require.False(t, list5.Equals(list4))
	require.True(t, list5.Equals(list5))
	require.True(t, list5.Equals(list6))

	require.False(t, list6.Equals(list1))
	require.False(t, list6.Equals(list2))
	require.False(t, list6.Equals(list3))
	require.False(t, list6.Equals(list4))
	require.True(t, list6.Equals(list5))
	require.True(t, list6.Equals(list6))
}

func TestLabelArrayListSort(t *testing.T) {
	require.Equal(t, LabelArrayList(nil), LabelArrayList(nil).Sort())
	require.Equal(t, LabelArrayList{}, LabelArrayList{}.Sort())

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

	require.Equal(t, expected1, list1.Sort())

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
	require.Equal(t, expected2, list2.Sort())
}

func TestModelsFromLabelArrayListString(t *testing.T) {
	arrayList := LabelArrayList{
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
	expected := [][]string{
		{""},
		{"reserved:aaa"},
		{"any:env=devel"},
		{"any:env=devel", "container:user=bob"},
		{"any:env=devel", "container:user=bob", "any:xyz"},
		{"any:foo=bar"},
	}

	i := 0
	for model := range ModelsFromLabelArrayListString(arrayList.String()) {
		require.Equal(t, expected[i], model)
		i++
	}
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
		require.Equal(t, tc.expected, a, tc.name)
		require.Equal(t, a.Sort(), a, tc.name+" returned unsorted result")

		a = tc.a.DeepCopy().Sort()
		b = tc.b.DeepCopy().Sort()
		as := a.String()
		bs := b.String()

		a.MergeSorted(b)
		require.Equal(t, tc.expected, a, tc.name+" MergeSorted")
		require.Equal(t, a.Sort(), a, tc.name+" MergeSorted returned unsorted result")

		as = MergeSortedLabelArrayListStrings(as, bs)
		require.Equal(t, tc.expected.String(), as, tc.name+" MergeSortedLabelArrayListStrings")
		require.Equal(t, a.Sort().String(), as, tc.name+" MergeSortedLabelArrayListStrings returned unsorted result")
	}
}
