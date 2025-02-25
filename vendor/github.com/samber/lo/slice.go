package lo

import (
	"sort"

	"github.com/samber/lo/internal/constraints"
	"github.com/samber/lo/internal/rand"
)

// Filter iterates over elements of collection, returning an array of all elements predicate returns truthy for.
// Play: https://go.dev/play/p/Apjg3WeSi7K
func Filter[T any, Slice ~[]T](collection Slice, predicate func(item T, index int) bool) Slice {
	result := make(Slice, 0, len(collection))

	for i := range collection {
		if predicate(collection[i], i) {
			result = append(result, collection[i])
		}
	}

	return result
}

// Map manipulates a slice and transforms it to a slice of another type.
// Play: https://go.dev/play/p/OkPcYAhBo0D
func Map[T any, R any](collection []T, iteratee func(item T, index int) R) []R {
	result := make([]R, len(collection))

	for i := range collection {
		result[i] = iteratee(collection[i], i)
	}

	return result
}

// FilterMap returns a slice which obtained after both filtering and mapping using the given callback function.
// The callback function should return two values:
//   - the result of the mapping operation and
//   - whether the result element should be included or not.
//
// Play: https://go.dev/play/p/-AuYXfy7opz
func FilterMap[T any, R any](collection []T, callback func(item T, index int) (R, bool)) []R {
	result := []R{}

	for i := range collection {
		if r, ok := callback(collection[i], i); ok {
			result = append(result, r)
		}
	}

	return result
}

// FlatMap manipulates a slice and transforms and flattens it to a slice of another type.
// The transform function can either return a slice or a `nil`, and in the `nil` case
// no value is added to the final slice.
// Play: https://go.dev/play/p/YSoYmQTA8-U
func FlatMap[T any, R any](collection []T, iteratee func(item T, index int) []R) []R {
	result := make([]R, 0, len(collection))

	for i := range collection {
		result = append(result, iteratee(collection[i], i)...)
	}

	return result
}

// Reduce reduces collection to a value which is the accumulated result of running each element in collection
// through accumulator, where each successive invocation is supplied the return value of the previous.
// Play: https://go.dev/play/p/R4UHXZNaaUG
func Reduce[T any, R any](collection []T, accumulator func(agg R, item T, index int) R, initial R) R {
	for i := range collection {
		initial = accumulator(initial, collection[i], i)
	}

	return initial
}

// ReduceRight helper is like Reduce except that it iterates over elements of collection from right to left.
// Play: https://go.dev/play/p/Fq3W70l7wXF
func ReduceRight[T any, R any](collection []T, accumulator func(agg R, item T, index int) R, initial R) R {
	for i := len(collection) - 1; i >= 0; i-- {
		initial = accumulator(initial, collection[i], i)
	}

	return initial
}

// ForEach iterates over elements of collection and invokes iteratee for each element.
// Play: https://go.dev/play/p/oofyiUPRf8t
func ForEach[T any](collection []T, iteratee func(item T, index int)) {
	for i := range collection {
		iteratee(collection[i], i)
	}
}

// ForEachWhile iterates over elements of collection and invokes iteratee for each element
// collection return value decide to continue or break, like do while().
// Play: https://go.dev/play/p/QnLGt35tnow
func ForEachWhile[T any](collection []T, iteratee func(item T, index int) (goon bool)) {
	for i := range collection {
		if !iteratee(collection[i], i) {
			break
		}
	}
}

// Times invokes the iteratee n times, returning an array of the results of each invocation.
// The iteratee is invoked with index as argument.
// Play: https://go.dev/play/p/vgQj3Glr6lT
func Times[T any](count int, iteratee func(index int) T) []T {
	result := make([]T, count)

	for i := 0; i < count; i++ {
		result[i] = iteratee(i)
	}

	return result
}

// Uniq returns a duplicate-free version of an array, in which only the first occurrence of each element is kept.
// The order of result values is determined by the order they occur in the array.
// Play: https://go.dev/play/p/DTzbeXZ6iEN
func Uniq[T comparable, Slice ~[]T](collection Slice) Slice {
	result := make(Slice, 0, len(collection))
	seen := make(map[T]struct{}, len(collection))

	for i := range collection {
		if _, ok := seen[collection[i]]; ok {
			continue
		}

		seen[collection[i]] = struct{}{}
		result = append(result, collection[i])
	}

	return result
}

// UniqBy returns a duplicate-free version of an array, in which only the first occurrence of each element is kept.
// The order of result values is determined by the order they occur in the array. It accepts `iteratee` which is
// invoked for each element in array to generate the criterion by which uniqueness is computed.
// Play: https://go.dev/play/p/g42Z3QSb53u
func UniqBy[T any, U comparable, Slice ~[]T](collection Slice, iteratee func(item T) U) Slice {
	result := make(Slice, 0, len(collection))
	seen := make(map[U]struct{}, len(collection))

	for i := range collection {
		key := iteratee(collection[i])

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, collection[i])
	}

	return result
}

// GroupBy returns an object composed of keys generated from the results of running each element of collection through iteratee.
// Play: https://go.dev/play/p/XnQBd_v6brd
func GroupBy[T any, U comparable, Slice ~[]T](collection Slice, iteratee func(item T) U) map[U]Slice {
	result := map[U]Slice{}

	for i := range collection {
		key := iteratee(collection[i])

		result[key] = append(result[key], collection[i])
	}

	return result
}

// Chunk returns an array of elements split into groups the length of size. If array can't be split evenly,
// the final chunk will be the remaining elements.
// Play: https://go.dev/play/p/EeKl0AuTehH
func Chunk[T any, Slice ~[]T](collection Slice, size int) []Slice {
	if size <= 0 {
		panic("Second parameter must be greater than 0")
	}

	chunksNum := len(collection) / size
	if len(collection)%size != 0 {
		chunksNum += 1
	}

	result := make([]Slice, 0, chunksNum)

	for i := 0; i < chunksNum; i++ {
		last := (i + 1) * size
		if last > len(collection) {
			last = len(collection)
		}
		result = append(result, collection[i*size:last:last])
	}

	return result
}

// PartitionBy returns an array of elements split into groups. The order of grouped values is
// determined by the order they occur in collection. The grouping is generated from the results
// of running each element of collection through iteratee.
// Play: https://go.dev/play/p/NfQ_nGjkgXW
func PartitionBy[T any, K comparable, Slice ~[]T](collection Slice, iteratee func(item T) K) []Slice {
	result := []Slice{}
	seen := map[K]int{}

	for i := range collection {
		key := iteratee(collection[i])

		resultIndex, ok := seen[key]
		if !ok {
			resultIndex = len(result)
			seen[key] = resultIndex
			result = append(result, Slice{})
		}

		result[resultIndex] = append(result[resultIndex], collection[i])
	}

	return result

	// unordered:
	// groups := GroupBy[T, K](collection, iteratee)
	// return Values[K, []T](groups)
}

// Flatten returns an array a single level deep.
// Play: https://go.dev/play/p/rbp9ORaMpjw
func Flatten[T any, Slice ~[]T](collection []Slice) Slice {
	totalLen := 0
	for i := range collection {
		totalLen += len(collection[i])
	}

	result := make(Slice, 0, totalLen)
	for i := range collection {
		result = append(result, collection[i]...)
	}

	return result
}

// Interleave round-robin alternating input slices and sequentially appending value at index into result
// Play: https://go.dev/play/p/-RJkTLQEDVt
func Interleave[T any, Slice ~[]T](collections ...Slice) Slice {
	if len(collections) == 0 {
		return Slice{}
	}

	maxSize := 0
	totalSize := 0
	for i := range collections {
		size := len(collections[i])
		totalSize += size
		if size > maxSize {
			maxSize = size
		}
	}

	if maxSize == 0 {
		return Slice{}
	}

	result := make(Slice, totalSize)

	resultIdx := 0
	for i := 0; i < maxSize; i++ {
		for j := range collections {
			if len(collections[j])-1 < i {
				continue
			}

			result[resultIdx] = collections[j][i]
			resultIdx++
		}
	}

	return result
}

// Shuffle returns an array of shuffled values. Uses the Fisher-Yates shuffle algorithm.
// Play: https://go.dev/play/p/Qp73bnTDnc7
func Shuffle[T any, Slice ~[]T](collection Slice) Slice {
	rand.Shuffle(len(collection), func(i, j int) {
		collection[i], collection[j] = collection[j], collection[i]
	})

	return collection
}

// Reverse reverses array so that the first element becomes the last, the second element becomes the second to last, and so on.
// Play: https://go.dev/play/p/fhUMLvZ7vS6
func Reverse[T any, Slice ~[]T](collection Slice) Slice {
	length := len(collection)
	half := length / 2

	for i := 0; i < half; i = i + 1 {
		j := length - 1 - i
		collection[i], collection[j] = collection[j], collection[i]
	}

	return collection
}

// Fill fills elements of array with `initial` value.
// Play: https://go.dev/play/p/VwR34GzqEub
func Fill[T Clonable[T]](collection []T, initial T) []T {
	result := make([]T, 0, len(collection))

	for range collection {
		result = append(result, initial.Clone())
	}

	return result
}

// Repeat builds a slice with N copies of initial value.
// Play: https://go.dev/play/p/g3uHXbmc3b6
func Repeat[T Clonable[T]](count int, initial T) []T {
	result := make([]T, 0, count)

	for i := 0; i < count; i++ {
		result = append(result, initial.Clone())
	}

	return result
}

// RepeatBy builds a slice with values returned by N calls of callback.
// Play: https://go.dev/play/p/ozZLCtX_hNU
func RepeatBy[T any](count int, predicate func(index int) T) []T {
	result := make([]T, 0, count)

	for i := 0; i < count; i++ {
		result = append(result, predicate(i))
	}

	return result
}

// KeyBy transforms a slice or an array of structs to a map based on a pivot callback.
// Play: https://go.dev/play/p/mdaClUAT-zZ
func KeyBy[K comparable, V any](collection []V, iteratee func(item V) K) map[K]V {
	result := make(map[K]V, len(collection))

	for i := range collection {
		k := iteratee(collection[i])
		result[k] = collection[i]
	}

	return result
}

// Associate returns a map containing key-value pairs provided by transform function applied to elements of the given slice.
// If any of two pairs would have the same key the last one gets added to the map.
// The order of keys in returned map is not specified and is not guaranteed to be the same from the original array.
// Play: https://go.dev/play/p/WHa2CfMO3Lr
func Associate[T any, K comparable, V any](collection []T, transform func(item T) (K, V)) map[K]V {
	result := make(map[K]V, len(collection))

	for i := range collection {
		k, v := transform(collection[i])
		result[k] = v
	}

	return result
}

// SliceToMap returns a map containing key-value pairs provided by transform function applied to elements of the given slice.
// If any of two pairs would have the same key the last one gets added to the map.
// The order of keys in returned map is not specified and is not guaranteed to be the same from the original array.
// Alias of Associate().
// Play: https://go.dev/play/p/WHa2CfMO3Lr
func SliceToMap[T any, K comparable, V any](collection []T, transform func(item T) (K, V)) map[K]V {
	return Associate(collection, transform)
}

// Drop drops n elements from the beginning of a slice or array.
// Play: https://go.dev/play/p/JswS7vXRJP2
func Drop[T any, Slice ~[]T](collection Slice, n int) Slice {
	if len(collection) <= n {
		return make(Slice, 0)
	}

	result := make(Slice, 0, len(collection)-n)

	return append(result, collection[n:]...)
}

// DropRight drops n elements from the end of a slice or array.
// Play: https://go.dev/play/p/GG0nXkSJJa3
func DropRight[T any, Slice ~[]T](collection Slice, n int) Slice {
	if len(collection) <= n {
		return Slice{}
	}

	result := make(Slice, 0, len(collection)-n)
	return append(result, collection[:len(collection)-n]...)
}

// DropWhile drops elements from the beginning of a slice or array while the predicate returns true.
// Play: https://go.dev/play/p/7gBPYw2IK16
func DropWhile[T any, Slice ~[]T](collection Slice, predicate func(item T) bool) Slice {
	i := 0
	for ; i < len(collection); i++ {
		if !predicate(collection[i]) {
			break
		}
	}

	result := make(Slice, 0, len(collection)-i)
	return append(result, collection[i:]...)
}

// DropRightWhile drops elements from the end of a slice or array while the predicate returns true.
// Play: https://go.dev/play/p/3-n71oEC0Hz
func DropRightWhile[T any, Slice ~[]T](collection Slice, predicate func(item T) bool) Slice {
	i := len(collection) - 1
	for ; i >= 0; i-- {
		if !predicate(collection[i]) {
			break
		}
	}

	result := make(Slice, 0, i+1)
	return append(result, collection[:i+1]...)
}

// DropByIndex drops elements from a slice or array by the index.
// A negative index will drop elements from the end of the slice.
// Play: https://go.dev/play/p/bPIH4npZRxS
func DropByIndex[T any](collection []T, indexes ...int) []T {
	initialSize := len(collection)
	if initialSize == 0 {
		return make([]T, 0)
	}

	for i := range indexes {
		if indexes[i] < 0 {
			indexes[i] = initialSize + indexes[i]
		}
	}

	indexes = Uniq(indexes)
	sort.Ints(indexes)

	result := make([]T, 0, initialSize)
	result = append(result, collection...)

	for i := range indexes {
		if indexes[i]-i < 0 || indexes[i]-i >= initialSize-i {
			continue
		}

		result = append(result[:indexes[i]-i], result[indexes[i]-i+1:]...)
	}

	return result
}

// Reject is the opposite of Filter, this method returns the elements of collection that predicate does not return truthy for.
// Play: https://go.dev/play/p/YkLMODy1WEL
func Reject[T any, Slice ~[]T](collection Slice, predicate func(item T, index int) bool) Slice {
	result := Slice{}

	for i := range collection {
		if !predicate(collection[i], i) {
			result = append(result, collection[i])
		}
	}

	return result
}

// RejectMap is the opposite of FilterMap, this method returns a slice which obtained after both filtering and mapping using the given callback function.
// The callback function should return two values:
//   - the result of the mapping operation and
//   - whether the result element should be included or not.
func RejectMap[T any, R any](collection []T, callback func(item T, index int) (R, bool)) []R {
	result := []R{}

	for i := range collection {
		if r, ok := callback(collection[i], i); !ok {
			result = append(result, r)
		}
	}

	return result
}

// FilterReject mixes Filter and Reject, this method returns two slices, one for the elements of collection that
// predicate returns truthy for and one for the elements that predicate does not return truthy for.
func FilterReject[T any, Slice ~[]T](collection Slice, predicate func(T, int) bool) (kept Slice, rejected Slice) {
	kept = make(Slice, 0, len(collection))
	rejected = make(Slice, 0, len(collection))

	for i := range collection {
		if predicate(collection[i], i) {
			kept = append(kept, collection[i])
		} else {
			rejected = append(rejected, collection[i])
		}
	}

	return kept, rejected
}

// Count counts the number of elements in the collection that compare equal to value.
// Play: https://go.dev/play/p/Y3FlK54yveC
func Count[T comparable](collection []T, value T) (count int) {
	for i := range collection {
		if collection[i] == value {
			count++
		}
	}

	return count
}

// CountBy counts the number of elements in the collection for which predicate is true.
// Play: https://go.dev/play/p/ByQbNYQQi4X
func CountBy[T any](collection []T, predicate func(item T) bool) (count int) {
	for i := range collection {
		if predicate(collection[i]) {
			count++
		}
	}

	return count
}

// CountValues counts the number of each element in the collection.
// Play: https://go.dev/play/p/-p-PyLT4dfy
func CountValues[T comparable](collection []T) map[T]int {
	result := make(map[T]int)

	for i := range collection {
		result[collection[i]]++
	}

	return result
}

// CountValuesBy counts the number of each element return from mapper function.
// Is equivalent to chaining lo.Map and lo.CountValues.
// Play: https://go.dev/play/p/2U0dG1SnOmS
func CountValuesBy[T any, U comparable](collection []T, mapper func(item T) U) map[U]int {
	result := make(map[U]int)

	for i := range collection {
		result[mapper(collection[i])]++
	}

	return result
}

// Subset returns a copy of a slice from `offset` up to `length` elements. Like `slice[start:start+length]`, but does not panic on overflow.
// Play: https://go.dev/play/p/tOQu1GhFcog
func Subset[T any, Slice ~[]T](collection Slice, offset int, length uint) Slice {
	size := len(collection)

	if offset < 0 {
		offset = size + offset
		if offset < 0 {
			offset = 0
		}
	}

	if offset > size {
		return Slice{}
	}

	if length > uint(size)-uint(offset) {
		length = uint(size - offset)
	}

	return collection[offset : offset+int(length)]
}

// Slice returns a copy of a slice from `start` up to, but not including `end`. Like `slice[start:end]`, but does not panic on overflow.
// Play: https://go.dev/play/p/8XWYhfMMA1h
func Slice[T any, Slice ~[]T](collection Slice, start int, end int) Slice {
	size := len(collection)

	if start >= end {
		return Slice{}
	}

	if start > size {
		start = size
	}
	if start < 0 {
		start = 0
	}

	if end > size {
		end = size
	}
	if end < 0 {
		end = 0
	}

	return collection[start:end]
}

// Replace returns a copy of the slice with the first n non-overlapping instances of old replaced by new.
// Play: https://go.dev/play/p/XfPzmf9gql6
func Replace[T comparable, Slice ~[]T](collection Slice, old T, new T, n int) Slice {
	result := make(Slice, len(collection))
	copy(result, collection)

	for i := range result {
		if result[i] == old && n != 0 {
			result[i] = new
			n--
		}
	}

	return result
}

// ReplaceAll returns a copy of the slice with all non-overlapping instances of old replaced by new.
// Play: https://go.dev/play/p/a9xZFUHfYcV
func ReplaceAll[T comparable, Slice ~[]T](collection Slice, old T, new T) Slice {
	return Replace(collection, old, new, -1)
}

// Compact returns a slice of all non-zero elements.
// Play: https://go.dev/play/p/tXiy-iK6PAc
func Compact[T comparable, Slice ~[]T](collection Slice) Slice {
	var zero T

	result := make(Slice, 0, len(collection))

	for i := range collection {
		if collection[i] != zero {
			result = append(result, collection[i])
		}
	}

	return result
}

// IsSorted checks if a slice is sorted.
// Play: https://go.dev/play/p/mc3qR-t4mcx
func IsSorted[T constraints.Ordered](collection []T) bool {
	for i := 1; i < len(collection); i++ {
		if collection[i-1] > collection[i] {
			return false
		}
	}

	return true
}

// IsSortedByKey checks if a slice is sorted by iteratee.
// Play: https://go.dev/play/p/wiG6XyBBu49
func IsSortedByKey[T any, K constraints.Ordered](collection []T, iteratee func(item T) K) bool {
	size := len(collection)

	for i := 0; i < size-1; i++ {
		if iteratee(collection[i]) > iteratee(collection[i+1]) {
			return false
		}
	}

	return true
}

// Splice inserts multiple elements at index i. A negative index counts back
// from the end of the slice. The helper is protected against overflow errors.
// Play: https://go.dev/play/p/G5_GhkeSUBA
func Splice[T any, Slice ~[]T](collection Slice, i int, elements ...T) Slice {
	sizeCollection := len(collection)
	sizeElements := len(elements)
	output := make(Slice, 0, sizeCollection+sizeElements) // preallocate memory for the output slice

	if sizeElements == 0 {
		return append(output, collection...) // simple copy
	} else if i > sizeCollection {
		// positive overflow
		return append(append(output, collection...), elements...)
	} else if i < -sizeCollection {
		// negative overflow
		return append(append(output, elements...), collection...)
	} else if i < 0 {
		// backward
		i = sizeCollection + i
	}

	return append(append(append(output, collection[:i]...), elements...), collection[i:]...)
}
