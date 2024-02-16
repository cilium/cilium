// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

// Counter tracks references for comparable .
//
// No thread safety is provided within this structure, the user is expected to
// handle concurrent access to this structure if it is used from multiple
// threads.
type Counter[T comparable] map[T]int

// Add increments the reference count for the specified key.
func (c Counter[T]) Add(key T) bool {
	value, exists := c[key]
	c[key] = value + 1
	return !exists
}

// Delete decrements the reference count for the specified key.
func (c Counter[T]) Delete(key T) bool {
	value := c[key]
	if value <= 1 {
		delete(c, key)
		return true
	}
	c[key] = value - 1
	return false
}

// DeepCopy makes a new copy of the received Counter.
func (c Counter[T]) DeepCopy() Counter[T] {
	result := make(Counter[T], len(c))
	for k, v := range c {
		result[k] = v
	}
	return result
}

// Deprecated. Use Counter[string] instead.
type StringCounter = Counter[string]
