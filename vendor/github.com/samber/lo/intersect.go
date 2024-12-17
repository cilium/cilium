package lo

// Contains returns true if an element is present in a collection.
func Contains[T comparable](collection []T, element T) bool {
	for i := range collection {
		if collection[i] == element {
			return true
		}
	}

	return false
}

// ContainsBy returns true if predicate function return true.
func ContainsBy[T any](collection []T, predicate func(item T) bool) bool {
	for i := range collection {
		if predicate(collection[i]) {
			return true
		}
	}

	return false
}

// Every returns true if all elements of a subset are contained into a collection or if the subset is empty.
func Every[T comparable](collection []T, subset []T) bool {
	for i := range subset {
		if !Contains(collection, subset[i]) {
			return false
		}
	}

	return true
}

// EveryBy returns true if the predicate returns true for all of the elements in the collection or if the collection is empty.
func EveryBy[T any](collection []T, predicate func(item T) bool) bool {
	for i := range collection {
		if !predicate(collection[i]) {
			return false
		}
	}

	return true
}

// Some returns true if at least 1 element of a subset is contained into a collection.
// If the subset is empty Some returns false.
func Some[T comparable](collection []T, subset []T) bool {
	for i := range subset {
		if Contains(collection, subset[i]) {
			return true
		}
	}

	return false
}

// SomeBy returns true if the predicate returns true for any of the elements in the collection.
// If the collection is empty SomeBy returns false.
func SomeBy[T any](collection []T, predicate func(item T) bool) bool {
	for i := range collection {
		if predicate(collection[i]) {
			return true
		}
	}

	return false
}

// None returns true if no element of a subset are contained into a collection or if the subset is empty.
func None[T comparable](collection []T, subset []T) bool {
	for i := range subset {
		if Contains(collection, subset[i]) {
			return false
		}
	}

	return true
}

// NoneBy returns true if the predicate returns true for none of the elements in the collection or if the collection is empty.
func NoneBy[T any](collection []T, predicate func(item T) bool) bool {
	for i := range collection {
		if predicate(collection[i]) {
			return false
		}
	}

	return true
}

// Intersect returns the intersection between two collections.
func Intersect[T comparable, Slice ~[]T](list1 Slice, list2 Slice) Slice {
	result := Slice{}
	seen := map[T]struct{}{}

	for i := range list1 {
		seen[list1[i]] = struct{}{}
	}

	for i := range list2 {
		if _, ok := seen[list2[i]]; ok {
			result = append(result, list2[i])
		}
	}

	return result
}

// Difference returns the difference between two collections.
// The first value is the collection of element absent of list2.
// The second value is the collection of element absent of list1.
func Difference[T comparable, Slice ~[]T](list1 Slice, list2 Slice) (Slice, Slice) {
	left := Slice{}
	right := Slice{}

	seenLeft := map[T]struct{}{}
	seenRight := map[T]struct{}{}

	for i := range list1 {
		seenLeft[list1[i]] = struct{}{}
	}

	for i := range list2 {
		seenRight[list2[i]] = struct{}{}
	}

	for i := range list1 {
		if _, ok := seenRight[list1[i]]; !ok {
			left = append(left, list1[i])
		}
	}

	for i := range list2 {
		if _, ok := seenLeft[list2[i]]; !ok {
			right = append(right, list2[i])
		}
	}

	return left, right
}

// Union returns all distinct elements from given collections.
// result returns will not change the order of elements relatively.
func Union[T comparable, Slice ~[]T](lists ...Slice) Slice {
	var capLen int

	for _, list := range lists {
		capLen += len(list)
	}

	result := make(Slice, 0, capLen)
	seen := make(map[T]struct{}, capLen)

	for i := range lists {
		for j := range lists[i] {
			if _, ok := seen[lists[i][j]]; !ok {
				seen[lists[i][j]] = struct{}{}
				result = append(result, lists[i][j])
			}
		}
	}

	return result
}

// Without returns slice excluding all given values.
func Without[T comparable, Slice ~[]T](collection Slice, exclude ...T) Slice {
	result := make(Slice, 0, len(collection))
	for i := range collection {
		if !Contains(exclude, collection[i]) {
			result = append(result, collection[i])
		}
	}
	return result
}

// WithoutEmpty returns slice excluding empty values.
//
// Deprecated: Use lo.Compact instead.
func WithoutEmpty[T comparable, Slice ~[]T](collection Slice) Slice {
	return Compact(collection)
}
