package lo

// Keys creates an array of the map keys.
// Play: https://go.dev/play/p/Uu11fHASqrU
func Keys[K comparable, V any](in ...map[K]V) []K {
	size := 0
	for i := range in {
		size += len(in[i])
	}
	result := make([]K, 0, size)

	for i := range in {
		for k := range in[i] {
			result = append(result, k)
		}
	}

	return result
}

// UniqKeys creates an array of unique keys in the map.
// Play: https://go.dev/play/p/TPKAb6ILdHk
func UniqKeys[K comparable, V any](in ...map[K]V) []K {
	size := 0
	for i := range in {
		size += len(in[i])
	}

	seen := make(map[K]struct{}, size)
	result := make([]K, 0)

	for i := range in {
		for k := range in[i] {
			if _, exists := seen[k]; exists {
				continue
			}
			seen[k] = struct{}{}
			result = append(result, k)
		}
	}

	return result
}

// HasKey returns whether the given key exists.
// Play: https://go.dev/play/p/aVwubIvECqS
func HasKey[K comparable, V any](in map[K]V, key K) bool {
	_, ok := in[key]
	return ok
}

// Values creates an array of the map values.
// Play: https://go.dev/play/p/nnRTQkzQfF6
func Values[K comparable, V any](in ...map[K]V) []V {
	size := 0
	for i := range in {
		size += len(in[i])
	}
	result := make([]V, 0, size)

	for i := range in {
		for k := range in[i] {
			result = append(result, in[i][k])
		}
	}

	return result
}

// UniqValues creates an array of unique values in the map.
// Play: https://go.dev/play/p/nf6bXMh7rM3
func UniqValues[K comparable, V comparable](in ...map[K]V) []V {
	size := 0
	for i := range in {
		size += len(in[i])
	}

	seen := make(map[V]struct{}, size)
	result := make([]V, 0)

	for i := range in {
		for k := range in[i] {
			val := in[i][k]
			if _, exists := seen[val]; exists {
				continue
			}
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	return result
}

// ValueOr returns the value of the given key or the fallback value if the key is not present.
// Play: https://go.dev/play/p/bAq9mHErB4V
func ValueOr[K comparable, V any](in map[K]V, key K, fallback V) V {
	if v, ok := in[key]; ok {
		return v
	}
	return fallback
}

// PickBy returns same map type filtered by given predicate.
// Play: https://go.dev/play/p/kdg8GR_QMmf
func PickBy[K comparable, V any, Map ~map[K]V](in Map, predicate func(key K, value V) bool) Map {
	r := Map{}
	for k := range in {
		if predicate(k, in[k]) {
			r[k] = in[k]
		}
	}
	return r
}

// PickByKeys returns same map type filtered by given keys.
// Play: https://go.dev/play/p/R1imbuci9qU
func PickByKeys[K comparable, V any, Map ~map[K]V](in Map, keys []K) Map {
	r := Map{}
	for i := range keys {
		if v, ok := in[keys[i]]; ok {
			r[keys[i]] = v
		}
	}
	return r
}

// PickByValues returns same map type filtered by given values.
// Play: https://go.dev/play/p/1zdzSvbfsJc
func PickByValues[K comparable, V comparable, Map ~map[K]V](in Map, values []V) Map {
	r := Map{}
	for k := range in {
		if Contains(values, in[k]) {
			r[k] = in[k]
		}
	}
	return r
}

// OmitBy returns same map type filtered by given predicate.
// Play: https://go.dev/play/p/EtBsR43bdsd
func OmitBy[K comparable, V any, Map ~map[K]V](in Map, predicate func(key K, value V) bool) Map {
	r := Map{}
	for k := range in {
		if !predicate(k, in[k]) {
			r[k] = in[k]
		}
	}
	return r
}

// OmitByKeys returns same map type filtered by given keys.
// Play: https://go.dev/play/p/t1QjCrs-ysk
func OmitByKeys[K comparable, V any, Map ~map[K]V](in Map, keys []K) Map {
	r := Map{}
	for k := range in {
		r[k] = in[k]
	}
	for i := range keys {
		delete(r, keys[i])
	}
	return r
}

// OmitByValues returns same map type filtered by given values.
// Play: https://go.dev/play/p/9UYZi-hrs8j
func OmitByValues[K comparable, V comparable, Map ~map[K]V](in Map, values []V) Map {
	r := Map{}
	for k := range in {
		if !Contains(values, in[k]) {
			r[k] = in[k]
		}
	}
	return r
}

// Entries transforms a map into array of key/value pairs.
// Play:
func Entries[K comparable, V any](in map[K]V) []Entry[K, V] {
	entries := make([]Entry[K, V], 0, len(in))

	for k := range in {
		entries = append(entries, Entry[K, V]{
			Key:   k,
			Value: in[k],
		})
	}

	return entries
}

// ToPairs transforms a map into array of key/value pairs.
// Alias of Entries().
// Play: https://go.dev/play/p/3Dhgx46gawJ
func ToPairs[K comparable, V any](in map[K]V) []Entry[K, V] {
	return Entries(in)
}

// FromEntries transforms an array of key/value pairs into a map.
// Play: https://go.dev/play/p/oIr5KHFGCEN
func FromEntries[K comparable, V any](entries []Entry[K, V]) map[K]V {
	out := make(map[K]V, len(entries))

	for i := range entries {
		out[entries[i].Key] = entries[i].Value
	}

	return out
}

// FromPairs transforms an array of key/value pairs into a map.
// Alias of FromEntries().
// Play: https://go.dev/play/p/oIr5KHFGCEN
func FromPairs[K comparable, V any](entries []Entry[K, V]) map[K]V {
	return FromEntries(entries)
}

// Invert creates a map composed of the inverted keys and values. If map
// contains duplicate values, subsequent values overwrite property assignments
// of previous values.
// Play: https://go.dev/play/p/rFQ4rak6iA1
func Invert[K comparable, V comparable](in map[K]V) map[V]K {
	out := make(map[V]K, len(in))

	for k := range in {
		out[in[k]] = k
	}

	return out
}

// Assign merges multiple maps from left to right.
// Play: https://go.dev/play/p/VhwfJOyxf5o
func Assign[K comparable, V any, Map ~map[K]V](maps ...Map) Map {
	count := 0
	for i := range maps {
		count += len(maps[i])
	}

	out := make(Map, count)
	for i := range maps {
		for k := range maps[i] {
			out[k] = maps[i][k]
		}
	}

	return out
}

// MapKeys manipulates a map keys and transforms it to a map of another type.
// Play: https://go.dev/play/p/9_4WPIqOetJ
func MapKeys[K comparable, V any, R comparable](in map[K]V, iteratee func(value V, key K) R) map[R]V {
	result := make(map[R]V, len(in))

	for k := range in {
		result[iteratee(in[k], k)] = in[k]
	}

	return result
}

// MapValues manipulates a map values and transforms it to a map of another type.
// Play: https://go.dev/play/p/T_8xAfvcf0W
func MapValues[K comparable, V any, R any](in map[K]V, iteratee func(value V, key K) R) map[K]R {
	result := make(map[K]R, len(in))

	for k := range in {
		result[k] = iteratee(in[k], k)
	}

	return result
}

// MapEntries manipulates a map entries and transforms it to a map of another type.
// Play: https://go.dev/play/p/VuvNQzxKimT
func MapEntries[K1 comparable, V1 any, K2 comparable, V2 any](in map[K1]V1, iteratee func(key K1, value V1) (K2, V2)) map[K2]V2 {
	result := make(map[K2]V2, len(in))

	for k1 := range in {
		k2, v2 := iteratee(k1, in[k1])
		result[k2] = v2
	}

	return result
}

// MapToSlice transforms a map into a slice based on specific iteratee
// Play: https://go.dev/play/p/ZuiCZpDt6LD
func MapToSlice[K comparable, V any, R any](in map[K]V, iteratee func(key K, value V) R) []R {
	result := make([]R, 0, len(in))

	for k := range in {
		result = append(result, iteratee(k, in[k]))
	}

	return result
}
