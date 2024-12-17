package lo

// T2 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T2[A, B any](a A, b B) Tuple2[A, B] {
	return Tuple2[A, B]{A: a, B: b}
}

// T3 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T3[A, B, C any](a A, b B, c C) Tuple3[A, B, C] {
	return Tuple3[A, B, C]{A: a, B: b, C: c}
}

// T4 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T4[A, B, C, D any](a A, b B, c C, d D) Tuple4[A, B, C, D] {
	return Tuple4[A, B, C, D]{A: a, B: b, C: c, D: d}
}

// T5 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T5[A, B, C, D, E any](a A, b B, c C, d D, e E) Tuple5[A, B, C, D, E] {
	return Tuple5[A, B, C, D, E]{A: a, B: b, C: c, D: d, E: e}
}

// T6 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T6[A, B, C, D, E, F any](a A, b B, c C, d D, e E, f F) Tuple6[A, B, C, D, E, F] {
	return Tuple6[A, B, C, D, E, F]{A: a, B: b, C: c, D: d, E: e, F: f}
}

// T7 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T7[A, B, C, D, E, F, G any](a A, b B, c C, d D, e E, f F, g G) Tuple7[A, B, C, D, E, F, G] {
	return Tuple7[A, B, C, D, E, F, G]{A: a, B: b, C: c, D: d, E: e, F: f, G: g}
}

// T8 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T8[A, B, C, D, E, F, G, H any](a A, b B, c C, d D, e E, f F, g G, h H) Tuple8[A, B, C, D, E, F, G, H] {
	return Tuple8[A, B, C, D, E, F, G, H]{A: a, B: b, C: c, D: d, E: e, F: f, G: g, H: h}
}

// T9 creates a tuple from a list of values.
// Play: https://go.dev/play/p/IllL3ZO4BQm
func T9[A, B, C, D, E, F, G, H, I any](a A, b B, c C, d D, e E, f F, g G, h H, i I) Tuple9[A, B, C, D, E, F, G, H, I] {
	return Tuple9[A, B, C, D, E, F, G, H, I]{A: a, B: b, C: c, D: d, E: e, F: f, G: g, H: h, I: i}
}

// Unpack2 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack2[A, B any](tuple Tuple2[A, B]) (A, B) {
	return tuple.A, tuple.B
}

// Unpack3 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack3[A, B, C any](tuple Tuple3[A, B, C]) (A, B, C) {
	return tuple.A, tuple.B, tuple.C
}

// Unpack4 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack4[A, B, C, D any](tuple Tuple4[A, B, C, D]) (A, B, C, D) {
	return tuple.A, tuple.B, tuple.C, tuple.D
}

// Unpack5 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack5[A, B, C, D, E any](tuple Tuple5[A, B, C, D, E]) (A, B, C, D, E) {
	return tuple.A, tuple.B, tuple.C, tuple.D, tuple.E
}

// Unpack6 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack6[A, B, C, D, E, F any](tuple Tuple6[A, B, C, D, E, F]) (A, B, C, D, E, F) {
	return tuple.A, tuple.B, tuple.C, tuple.D, tuple.E, tuple.F
}

// Unpack7 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack7[A, B, C, D, E, F, G any](tuple Tuple7[A, B, C, D, E, F, G]) (A, B, C, D, E, F, G) {
	return tuple.A, tuple.B, tuple.C, tuple.D, tuple.E, tuple.F, tuple.G
}

// Unpack8 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack8[A, B, C, D, E, F, G, H any](tuple Tuple8[A, B, C, D, E, F, G, H]) (A, B, C, D, E, F, G, H) {
	return tuple.A, tuple.B, tuple.C, tuple.D, tuple.E, tuple.F, tuple.G, tuple.H
}

// Unpack9 returns values contained in tuple.
// Play: https://go.dev/play/p/xVP_k0kJ96W
func Unpack9[A, B, C, D, E, F, G, H, I any](tuple Tuple9[A, B, C, D, E, F, G, H, I]) (A, B, C, D, E, F, G, H, I) {
	return tuple.A, tuple.B, tuple.C, tuple.D, tuple.E, tuple.F, tuple.G, tuple.H, tuple.I
}

// Zip2 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip2[A, B any](a []A, b []B) []Tuple2[A, B] {
	size := Max([]int{len(a), len(b)})

	result := make([]Tuple2[A, B], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)

		result = append(result, Tuple2[A, B]{
			A: _a,
			B: _b,
		})
	}

	return result
}

// Zip3 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip3[A, B, C any](a []A, b []B, c []C) []Tuple3[A, B, C] {
	size := Max([]int{len(a), len(b), len(c)})

	result := make([]Tuple3[A, B, C], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)

		result = append(result, Tuple3[A, B, C]{
			A: _a,
			B: _b,
			C: _c,
		})
	}

	return result
}

// Zip4 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip4[A, B, C, D any](a []A, b []B, c []C, d []D) []Tuple4[A, B, C, D] {
	size := Max([]int{len(a), len(b), len(c), len(d)})

	result := make([]Tuple4[A, B, C, D], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)

		result = append(result, Tuple4[A, B, C, D]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
		})
	}

	return result
}

// Zip5 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip5[A, B, C, D, E any](a []A, b []B, c []C, d []D, e []E) []Tuple5[A, B, C, D, E] {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e)})

	result := make([]Tuple5[A, B, C, D, E], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)

		result = append(result, Tuple5[A, B, C, D, E]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
			E: _e,
		})
	}

	return result
}

// Zip6 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip6[A, B, C, D, E, F any](a []A, b []B, c []C, d []D, e []E, f []F) []Tuple6[A, B, C, D, E, F] {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f)})

	result := make([]Tuple6[A, B, C, D, E, F], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)

		result = append(result, Tuple6[A, B, C, D, E, F]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
			E: _e,
			F: _f,
		})
	}

	return result
}

// Zip7 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip7[A, B, C, D, E, F, G any](a []A, b []B, c []C, d []D, e []E, f []F, g []G) []Tuple7[A, B, C, D, E, F, G] {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f), len(g)})

	result := make([]Tuple7[A, B, C, D, E, F, G], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)

		result = append(result, Tuple7[A, B, C, D, E, F, G]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
			E: _e,
			F: _f,
			G: _g,
		})
	}

	return result
}

// Zip8 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip8[A, B, C, D, E, F, G, H any](a []A, b []B, c []C, d []D, e []E, f []F, g []G, h []H) []Tuple8[A, B, C, D, E, F, G, H] {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f), len(g), len(h)})

	result := make([]Tuple8[A, B, C, D, E, F, G, H], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)
		_h, _ := Nth(h, index)

		result = append(result, Tuple8[A, B, C, D, E, F, G, H]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
			E: _e,
			F: _f,
			G: _g,
			H: _h,
		})
	}

	return result
}

// Zip9 creates a slice of grouped elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
// Play: https://go.dev/play/p/jujaA6GaJTp
func Zip9[A, B, C, D, E, F, G, H, I any](a []A, b []B, c []C, d []D, e []E, f []F, g []G, h []H, i []I) []Tuple9[A, B, C, D, E, F, G, H, I] {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f), len(g), len(h), len(i)})

	result := make([]Tuple9[A, B, C, D, E, F, G, H, I], 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)
		_h, _ := Nth(h, index)
		_i, _ := Nth(i, index)

		result = append(result, Tuple9[A, B, C, D, E, F, G, H, I]{
			A: _a,
			B: _b,
			C: _c,
			D: _d,
			E: _e,
			F: _f,
			G: _g,
			H: _h,
			I: _i,
		})
	}

	return result
}

// ZipBy2 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy2[A any, B any, Out any](a []A, b []B, iteratee func(a A, b B) Out) []Out {
	size := Max([]int{len(a), len(b)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)

		result = append(result, iteratee(_a, _b))
	}

	return result
}

// ZipBy3 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy3[A any, B any, C any, Out any](a []A, b []B, c []C, iteratee func(a A, b B, c C) Out) []Out {
	size := Max([]int{len(a), len(b), len(c)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)

		result = append(result, iteratee(_a, _b, _c))
	}

	return result
}

// ZipBy4 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy4[A any, B any, C any, D any, Out any](a []A, b []B, c []C, d []D, iteratee func(a A, b B, c C, d D) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)

		result = append(result, iteratee(_a, _b, _c, _d))
	}

	return result
}

// ZipBy5 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy5[A any, B any, C any, D any, E any, Out any](a []A, b []B, c []C, d []D, e []E, iteratee func(a A, b B, c C, d D, e E) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)

		result = append(result, iteratee(_a, _b, _c, _d, _e))
	}

	return result
}

// ZipBy6 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy6[A any, B any, C any, D any, E any, F any, Out any](a []A, b []B, c []C, d []D, e []E, f []F, iteratee func(a A, b B, c C, d D, e E, f F) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)

		result = append(result, iteratee(_a, _b, _c, _d, _e, _f))
	}

	return result
}

// ZipBy7 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy7[A any, B any, C any, D any, E any, F any, G any, Out any](a []A, b []B, c []C, d []D, e []E, f []F, g []G, iteratee func(a A, b B, c C, d D, e E, f F, g G) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)

		result = append(result, iteratee(_a, _b, _c, _d, _e, _f, _g))
	}

	return result
}

// ZipBy8 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy8[A any, B any, C any, D any, E any, F any, G any, H any, Out any](a []A, b []B, c []C, d []D, e []E, f []F, g []G, h []H, iteratee func(a A, b B, c C, d D, e E, f F, g G, h H) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f), len(g)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)
		_h, _ := Nth(h, index)

		result = append(result, iteratee(_a, _b, _c, _d, _e, _f, _g, _h))
	}

	return result
}

// ZipBy9 creates a slice of transformed elements, the first of which contains the first elements
// of the given arrays, the second of which contains the second elements of the given arrays, and so on.
// When collections have different size, the Tuple attributes are filled with zero value.
func ZipBy9[A any, B any, C any, D any, E any, F any, G any, H any, I any, Out any](a []A, b []B, c []C, d []D, e []E, f []F, g []G, h []H, i []I, iteratee func(a A, b B, c C, d D, e E, f F, g G, h H, i I) Out) []Out {
	size := Max([]int{len(a), len(b), len(c), len(d), len(e), len(f), len(g), len(h), len(i)})

	result := make([]Out, 0, size)

	for index := 0; index < size; index++ {
		_a, _ := Nth(a, index)
		_b, _ := Nth(b, index)
		_c, _ := Nth(c, index)
		_d, _ := Nth(d, index)
		_e, _ := Nth(e, index)
		_f, _ := Nth(f, index)
		_g, _ := Nth(g, index)
		_h, _ := Nth(h, index)
		_i, _ := Nth(i, index)

		result = append(result, iteratee(_a, _b, _c, _d, _e, _f, _g, _h, _i))
	}

	return result
}

// Unzip2 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip2[A, B any](tuples []Tuple2[A, B]) ([]A, []B) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
	}

	return r1, r2
}

// Unzip3 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip3[A, B, C any](tuples []Tuple3[A, B, C]) ([]A, []B, []C) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
	}

	return r1, r2, r3
}

// Unzip4 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip4[A, B, C, D any](tuples []Tuple4[A, B, C, D]) ([]A, []B, []C, []D) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
	}

	return r1, r2, r3, r4
}

// Unzip5 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip5[A, B, C, D, E any](tuples []Tuple5[A, B, C, D, E]) ([]A, []B, []C, []D, []E) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
		r5 = append(r5, tuples[i].E)
	}

	return r1, r2, r3, r4, r5
}

// Unzip6 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip6[A, B, C, D, E, F any](tuples []Tuple6[A, B, C, D, E, F]) ([]A, []B, []C, []D, []E, []F) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
		r5 = append(r5, tuples[i].E)
		r6 = append(r6, tuples[i].F)
	}

	return r1, r2, r3, r4, r5, r6
}

// Unzip7 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip7[A, B, C, D, E, F, G any](tuples []Tuple7[A, B, C, D, E, F, G]) ([]A, []B, []C, []D, []E, []F, []G) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
		r5 = append(r5, tuples[i].E)
		r6 = append(r6, tuples[i].F)
		r7 = append(r7, tuples[i].G)
	}

	return r1, r2, r3, r4, r5, r6, r7
}

// Unzip8 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip8[A, B, C, D, E, F, G, H any](tuples []Tuple8[A, B, C, D, E, F, G, H]) ([]A, []B, []C, []D, []E, []F, []G, []H) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)
	r8 := make([]H, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
		r5 = append(r5, tuples[i].E)
		r6 = append(r6, tuples[i].F)
		r7 = append(r7, tuples[i].G)
		r8 = append(r8, tuples[i].H)
	}

	return r1, r2, r3, r4, r5, r6, r7, r8
}

// Unzip9 accepts an array of grouped elements and creates an array regrouping the elements
// to their pre-zip configuration.
// Play: https://go.dev/play/p/ciHugugvaAW
func Unzip9[A, B, C, D, E, F, G, H, I any](tuples []Tuple9[A, B, C, D, E, F, G, H, I]) ([]A, []B, []C, []D, []E, []F, []G, []H, []I) {
	size := len(tuples)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)
	r8 := make([]H, 0, size)
	r9 := make([]I, 0, size)

	for i := range tuples {
		r1 = append(r1, tuples[i].A)
		r2 = append(r2, tuples[i].B)
		r3 = append(r3, tuples[i].C)
		r4 = append(r4, tuples[i].D)
		r5 = append(r5, tuples[i].E)
		r6 = append(r6, tuples[i].F)
		r7 = append(r7, tuples[i].G)
		r8 = append(r8, tuples[i].H)
		r9 = append(r9, tuples[i].I)
	}

	return r1, r2, r3, r4, r5, r6, r7, r8, r9
}

// UnzipBy2 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy2[In any, A any, B any](items []In, iteratee func(In) (a A, b B)) ([]A, []B) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)

	for i := range items {
		a, b := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
	}

	return r1, r2
}

// UnzipBy3 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy3[In any, A any, B any, C any](items []In, iteratee func(In) (a A, b B, c C)) ([]A, []B, []C) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)

	for i := range items {
		a, b, c := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
	}

	return r1, r2, r3
}

// UnzipBy4 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy4[In any, A any, B any, C any, D any](items []In, iteratee func(In) (a A, b B, c C, d D)) ([]A, []B, []C, []D) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)

	for i := range items {
		a, b, c, d := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
	}

	return r1, r2, r3, r4
}

// UnzipBy5 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy5[In any, A any, B any, C any, D any, E any](items []In, iteratee func(In) (a A, b B, c C, d D, e E)) ([]A, []B, []C, []D, []E) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)

	for i := range items {
		a, b, c, d, e := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
		r5 = append(r5, e)
	}

	return r1, r2, r3, r4, r5
}

// UnzipBy6 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy6[In any, A any, B any, C any, D any, E any, F any](items []In, iteratee func(In) (a A, b B, c C, d D, e E, f F)) ([]A, []B, []C, []D, []E, []F) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)

	for i := range items {
		a, b, c, d, e, f := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
		r5 = append(r5, e)
		r6 = append(r6, f)
	}

	return r1, r2, r3, r4, r5, r6
}

// UnzipBy7 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy7[In any, A any, B any, C any, D any, E any, F any, G any](items []In, iteratee func(In) (a A, b B, c C, d D, e E, f F, g G)) ([]A, []B, []C, []D, []E, []F, []G) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)

	for i := range items {
		a, b, c, d, e, f, g := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
		r5 = append(r5, e)
		r6 = append(r6, f)
		r7 = append(r7, g)
	}

	return r1, r2, r3, r4, r5, r6, r7
}

// UnzipBy8 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy8[In any, A any, B any, C any, D any, E any, F any, G any, H any](items []In, iteratee func(In) (a A, b B, c C, d D, e E, f F, g G, h H)) ([]A, []B, []C, []D, []E, []F, []G, []H) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)
	r8 := make([]H, 0, size)

	for i := range items {
		a, b, c, d, e, f, g, h := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
		r5 = append(r5, e)
		r6 = append(r6, f)
		r7 = append(r7, g)
		r8 = append(r8, h)
	}

	return r1, r2, r3, r4, r5, r6, r7, r8
}

// UnzipBy9 iterates over a collection and creates an array regrouping the elements
// to their pre-zip configuration.
func UnzipBy9[In any, A any, B any, C any, D any, E any, F any, G any, H any, I any](items []In, iteratee func(In) (a A, b B, c C, d D, e E, f F, g G, h H, i I)) ([]A, []B, []C, []D, []E, []F, []G, []H, []I) {
	size := len(items)
	r1 := make([]A, 0, size)
	r2 := make([]B, 0, size)
	r3 := make([]C, 0, size)
	r4 := make([]D, 0, size)
	r5 := make([]E, 0, size)
	r6 := make([]F, 0, size)
	r7 := make([]G, 0, size)
	r8 := make([]H, 0, size)
	r9 := make([]I, 0, size)

	for i := range items {
		a, b, c, d, e, f, g, h, i := iteratee(items[i])
		r1 = append(r1, a)
		r2 = append(r2, b)
		r3 = append(r3, c)
		r4 = append(r4, d)
		r5 = append(r5, e)
		r6 = append(r6, f)
		r7 = append(r7, g)
		r8 = append(r8, h)
		r9 = append(r9, i)
	}

	return r1, r2, r3, r4, r5, r6, r7, r8, r9
}
