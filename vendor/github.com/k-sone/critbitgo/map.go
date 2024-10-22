package critbitgo

import (
	"unsafe"
)

// The map is sorted according to the natural ordering of its keys
type SortedMap struct {
	trie *Trie
}

func (m *SortedMap) Contains(key string) bool {
	return m.trie.Contains(*(*[]byte)(unsafe.Pointer(&key)))
}

func (m *SortedMap) Get(key string) (value interface{}, ok bool) {
	return m.trie.Get(*(*[]byte)(unsafe.Pointer(&key)))
}

func (m *SortedMap) Set(key string, value interface{}) {
	m.trie.Set([]byte(key), value)
}

func (m *SortedMap) Delete(key string) (value interface{}, ok bool) {
	return m.trie.Delete(*(*[]byte)(unsafe.Pointer(&key)))
}

func (m *SortedMap) Clear() {
	m.trie.Clear()
}

func (m *SortedMap) Size() int {
	return m.trie.Size()
}

// Returns a slice of sorted keys
func (m *SortedMap) Keys() []string {
	keys := make([]string, 0, m.Size())
	m.trie.Allprefixed([]byte{}, func(k []byte, v interface{}) bool {
		keys = append(keys, string(k))
		return true
	})
	return keys
}

// Executes a provided function for each element that has a given prefix.
// if handle returns `false`, the iteration is aborted.
func (m *SortedMap) Each(prefix string, handle func(key string, value interface{}) bool) bool {
	return m.trie.Allprefixed([]byte(prefix), func(k []byte, v interface{}) bool {
		return handle(string(k), v)
	})
}

// Create a SortedMap
func NewSortedMap() *SortedMap {
	return &SortedMap{NewTrie()}
}
