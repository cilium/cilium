# lo - Iterate over slices, maps, channels...

[![tag](https://img.shields.io/github/tag/samber/lo.svg)](https://github.com/samber/lo/releases)
![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.18-%23007d9c)
[![GoDoc](https://godoc.org/github.com/samber/lo?status.svg)](https://pkg.go.dev/github.com/samber/lo)
![Build Status](https://github.com/samber/lo/actions/workflows/test.yml/badge.svg)
[![Go report](https://goreportcard.com/badge/github.com/samber/lo)](https://goreportcard.com/report/github.com/samber/lo)
[![Coverage](https://img.shields.io/codecov/c/github/samber/lo)](https://codecov.io/gh/samber/lo)
[![Contributors](https://img.shields.io/github/contributors/samber/lo)](https://github.com/samber/lo/graphs/contributors)
[![License](https://img.shields.io/github/license/samber/lo)](./LICENSE)

✨ **`samber/lo` is a Lodash-style Go library based on Go 1.18+ Generics.**

This project started as an experiment with the new generics implementation. It may look like [Lodash](https://github.com/lodash/lodash) in some aspects. I used to code with the fantastic ["go-funk"](https://github.com/thoas/go-funk) package, but "go-funk" uses reflection and therefore is not typesafe.

As expected, benchmarks demonstrate that generics are much faster than implementations based on the "reflect" package. Benchmarks also show similar performance gains compared to pure `for` loops. [See below](#-benchmark).

In the future, 5 to 10 helpers will overlap with those coming into the Go standard library (under package names `slices` and `maps`). I feel this library is legitimate and offers many more valuable abstractions.

**See also:**

- [samber/do](https://github.com/samber/do): A dependency injection toolkit based on Go 1.18+ Generics
- [samber/mo](https://github.com/samber/mo): Monads based on Go 1.18+ Generics (Option, Result, Either...)

**Why this name?**

I wanted a **short name**, similar to "Lodash" and no Go package uses this name.

![lo](img/logo-full.png)

## 🚀 Install

```sh
go get github.com/samber/lo@v1
```

This library is v1 and follows SemVer strictly.

No breaking changes will be made to exported APIs before v2.0.0.

This library has no dependencies outside the Go standard library.

## 💡 Usage

You can import `lo` using:

```go
import (
    "github.com/samber/lo"
    lop "github.com/samber/lo/parallel"
)
```

Then use one of the helpers below:

```go
names := lo.Uniq([]string{"Samuel", "John", "Samuel"})
// []string{"Samuel", "John"}
```

Most of the time, the compiler will be able to infer the type so that you can call: `lo.Uniq([]string{...})`.

### Tips for lazy developers

I cannot recommend it, but in case you are too lazy for repeating `lo.` everywhere, you can import the entire library into the namespace.

```go
import (
    . "github.com/samber/lo"
)
```

I take no responsibility on this junk. 😁 💩

## 🤠 Spec

GoDoc: [https://godoc.org/github.com/samber/lo](https://godoc.org/github.com/samber/lo)

Supported helpers for slices:

- [Filter](#filter)
- [Map](#map)
- [FilterMap](#filtermap)
- [FlatMap](#flatmap)
- [Reduce](#reduce)
- [ReduceRight](#reduceright)
- [ForEach](#foreach)
- [ForEachWhile](#foreachwhile)
- [Times](#times)
- [Uniq](#uniq)
- [UniqBy](#uniqby)
- [GroupBy](#groupby)
- [Chunk](#chunk)
- [PartitionBy](#partitionby)
- [Flatten](#flatten)
- [Interleave](#interleave)
- [Shuffle](#shuffle)
- [Reverse](#reverse)
- [Fill](#fill)
- [Repeat](#repeat)
- [RepeatBy](#repeatby)
- [KeyBy](#keyby)
- [Associate / SliceToMap](#associate-alias-slicetomap)
- [Drop](#drop)
- [DropRight](#dropright)
- [DropWhile](#dropwhile)
- [DropRightWhile](#droprightwhile)
- [DropByIndex](#DropByIndex)
- [Reject](#reject)
- [RejectMap](#rejectmap)
- [FilterReject](#filterreject)
- [Count](#count)
- [CountBy](#countby)
- [CountValues](#countvalues)
- [CountValuesBy](#countvaluesby)
- [Subset](#subset)
- [Slice](#slice)
- [Replace](#replace)
- [ReplaceAll](#replaceall)
- [Compact](#compact)
- [IsSorted](#issorted)
- [IsSortedByKey](#issortedbykey)
- [Splice](#Splice)

Supported helpers for maps:

- [Keys](#keys)
- [UniqKeys](#uniqkeys)
- [HasKey](#haskey)
- [ValueOr](#valueor)
- [Values](#values)
- [UniqValues](#uniqvalues)
- [PickBy](#pickby)
- [PickByKeys](#pickbykeys)
- [PickByValues](#pickbyvalues)
- [OmitBy](#omitby)
- [OmitByKeys](#omitbykeys)
- [OmitByValues](#omitbyvalues)
- [Entries / ToPairs](#entries-alias-topairs)
- [FromEntries / FromPairs](#fromentries-alias-frompairs)
- [Invert](#invert)
- [Assign (merge of maps)](#assign)
- [MapKeys](#mapkeys)
- [MapValues](#mapvalues)
- [MapEntries](#mapentries)
- [MapToSlice](#maptoslice)

Supported math helpers:

- [Range / RangeFrom / RangeWithSteps](#range--rangefrom--rangewithsteps)
- [Clamp](#clamp)
- [Sum](#sum)
- [SumBy](#sumby)
- [Mean](#mean)
- [MeanBy](#meanby)

Supported helpers for strings:

- [RandomString](#randomstring)
- [Substring](#substring)
- [ChunkString](#chunkstring)
- [RuneLength](#runelength)
- [PascalCase](#pascalcase)
- [CamelCase](#camelcase)
- [KebabCase](#kebabcase)
- [SnakeCase](#snakecase)
- [Words](#words)
- [Capitalize](#capitalize)
- [Elipse](#elipse)

Supported helpers for tuples:

- [T2 -> T9](#t2---t9)
- [Unpack2 -> Unpack9](#unpack2---unpack9)
- [Zip2 -> Zip9](#zip2---zip9)
- [ZipBy2 -> ZipBy9](#zipby2---zipby9)
- [Unzip2 -> Unzip9](#unzip2---unzip9)
- [UnzipBy2 -> UnzipBy9](#unzipby2---unzipby9)

Supported helpers for time and duration:

- [Duration](#duration)
- [Duration0 -> Duration10](#duration0-duration10)

Supported helpers for channels:

- [ChannelDispatcher](#channeldispatcher)
- [SliceToChannel](#slicetochannel)
- [Generator](#generator)
- [Buffer](#buffer)
- [BufferWithTimeout](#bufferwithtimeout)
- [FanIn](#fanin)
- [FanOut](#fanout)

Supported intersection helpers:

- [Contains](#contains)
- [ContainsBy](#containsby)
- [Every](#every)
- [EveryBy](#everyby)
- [Some](#some)
- [SomeBy](#someby)
- [None](#none)
- [NoneBy](#noneby)
- [Intersect](#intersect)
- [Difference](#difference)
- [Union](#union)
- [Without](#without)
- [WithoutEmpty](#withoutempty)

Supported search helpers:

- [IndexOf](#indexof)
- [LastIndexOf](#lastindexof)
- [Find](#find)
- [FindIndexOf](#findindexof)
- [FindLastIndexOf](#findlastindexof)
- [FindOrElse](#findorelse)
- [FindKey](#findkey)
- [FindKeyBy](#findkeyby)
- [FindUniques](#finduniques)
- [FindUniquesBy](#finduniquesby)
- [FindDuplicates](#findduplicates)
- [FindDuplicatesBy](#findduplicatesby)
- [Min](#min)
- [MinBy](#minby)
- [Earliest](#earliest)
- [EarliestBy](#earliestby)
- [Max](#max)
- [MaxBy](#maxby)
- [Latest](#latest)
- [LatestBy](#latestby)
- [First](#first)
- [FirstOrEmpty](#FirstOrEmpty)
- [FirstOr](#FirstOr)
- [Last](#last)
- [LastOrEmpty](#LastOrEmpty)
- [LastOr](#LastOr)
- [Nth](#nth)
- [Sample](#sample)
- [Samples](#samples)

Conditional helpers:

- [Ternary](#ternary)
- [TernaryF](#ternaryf)
- [If / ElseIf / Else](#if--elseif--else)
- [Switch / Case / Default](#switch--case--default)

Type manipulation helpers:

- [IsNil](#isnil)
- [ToPtr](#toptr)
- [Nil](#nil)
- [EmptyableToPtr](#emptyabletoptr)
- [FromPtr](#fromptr)
- [FromPtrOr](#fromptror)
- [ToSlicePtr](#tosliceptr)
- [FromSlicePtr](#fromsliceptr)
- [FromSlicePtrOr](#fromsliceptror)
- [ToAnySlice](#toanyslice)
- [FromAnySlice](#fromanyslice)
- [Empty](#empty)
- [IsEmpty](#isempty)
- [IsNotEmpty](#isnotempty)
- [Coalesce](#coalesce)
- [CoalesceOrEmpty](#coalesceorempty)

Function helpers:

- [Partial](#partial)
- [Partial2 -> Partial5](#partial2---partial5)

Concurrency helpers:

- [Attempt](#attempt)
- [AttemptWhile](#attemptwhile)
- [AttemptWithDelay](#attemptwithdelay)
- [AttemptWhileWithDelay](#attemptwhilewithdelay)
- [Debounce](#debounce)
- [DebounceBy](#debounceby)
- [Synchronize](#synchronize)
- [Async](#async)
- [Transaction](#transaction)
- [WaitFor](#waitfor)
- [WaitForWithContext](#waitforwithcontext)

Error handling:

- [Validate](#validate)
- [Must](#must)
- [Try](#try)
- [Try1 -> Try6](#try0-6)
- [TryOr](#tryor)
- [TryOr1 -> TryOr6](#tryor0-6)
- [TryCatch](#trycatch)
- [TryWithErrorValue](#trywitherrorvalue)
- [TryCatchWithErrorValue](#trycatchwitherrorvalue)
- [ErrorsAs](#errorsas)

Constraints:

- Clonable

### Filter

Iterates over a collection and returns an array of all the elements the predicate function returns `true` for.

```go
even := lo.Filter([]int{1, 2, 3, 4}, func(x int, index int) bool {
    return x%2 == 0
})
// []int{2, 4}
```

[[play](https://go.dev/play/p/Apjg3WeSi7K)]

### Map

Manipulates a slice of one type and transforms it into a slice of another type:

```go
import "github.com/samber/lo"

lo.Map([]int64{1, 2, 3, 4}, func(x int64, index int) string {
    return strconv.FormatInt(x, 10)
})
// []string{"1", "2", "3", "4"}
```

[[play](https://go.dev/play/p/OkPcYAhBo0D)]

Parallel processing: like `lo.Map()`, but the mapper function is called in a goroutine. Results are returned in the same order.

```go
import lop "github.com/samber/lo/parallel"

lop.Map([]int64{1, 2, 3, 4}, func(x int64, _ int) string {
    return strconv.FormatInt(x, 10)
})
// []string{"1", "2", "3", "4"}
```

### FilterMap

Returns a slice which obtained after both filtering and mapping using the given callback function.

The callback function should return two values: the result of the mapping operation and whether the result element should be included or not.

```go
matching := lo.FilterMap([]string{"cpu", "gpu", "mouse", "keyboard"}, func(x string, _ int) (string, bool) {
    if strings.HasSuffix(x, "pu") {
        return "xpu", true
    }
    return "", false
})
// []string{"xpu", "xpu"}
```

[[play](https://go.dev/play/p/-AuYXfy7opz)]

### FlatMap

Manipulates a slice and transforms and flattens it to a slice of another type. The transform function can either return a slice or a `nil`, and in the `nil` case no value is added to the final slice.

```go
lo.FlatMap([]int64{0, 1, 2}, func(x int64, _ int) []string {
    return []string{
        strconv.FormatInt(x, 10),
        strconv.FormatInt(x, 10),
    }
})
// []string{"0", "0", "1", "1", "2", "2"}
```

[[play](https://go.dev/play/p/YSoYmQTA8-U)]

### Reduce

Reduces a collection to a single value. The value is calculated by accumulating the result of running each element in the collection through an accumulator function. Each successive invocation is supplied with the return value returned by the previous call.

```go
sum := lo.Reduce([]int{1, 2, 3, 4}, func(agg int, item int, _ int) int {
    return agg + item
}, 0)
// 10
```

[[play](https://go.dev/play/p/R4UHXZNaaUG)]

### ReduceRight

Like `lo.Reduce` except that it iterates over elements of collection from right to left.

```go
result := lo.ReduceRight([][]int{{0, 1}, {2, 3}, {4, 5}}, func(agg []int, item []int, _ int) []int {
    return append(agg, item...)
}, []int{})
// []int{4, 5, 2, 3, 0, 1}
```

[[play](https://go.dev/play/p/Fq3W70l7wXF)]

### ForEach

Iterates over elements of a collection and invokes the function over each element.

```go
import "github.com/samber/lo"

lo.ForEach([]string{"hello", "world"}, func(x string, _ int) {
    println(x)
})
// prints "hello\nworld\n"
```

[[play](https://go.dev/play/p/oofyiUPRf8t)]

Parallel processing: like `lo.ForEach()`, but the callback is called as a goroutine.

```go
import lop "github.com/samber/lo/parallel"

lop.ForEach([]string{"hello", "world"}, func(x string, _ int) {
    println(x)
})
// prints "hello\nworld\n" or "world\nhello\n"
```

### ForEachWhile

Iterates over collection elements and invokes iteratee for each element collection return value decide to continue or break, like do while().

```go
list := []int64{1, 2, -42, 4}

lo.ForEachWhile(list, func(x int64, _ int) bool {
	if x < 0 {
		return false
	}
	fmt.Println(x)
	return true
})
// 1
// 2
```

[[play](https://go.dev/play/p/QnLGt35tnow)]

### Times

Times invokes the iteratee n times, returning an array of the results of each invocation. The iteratee is invoked with index as argument.

```go
import "github.com/samber/lo"

lo.Times(3, func(i int) string {
    return strconv.FormatInt(int64(i), 10)
})
// []string{"0", "1", "2"}
```

[[play](https://go.dev/play/p/vgQj3Glr6lT)]

Parallel processing: like `lo.Times()`, but callback is called in goroutine.

```go
import lop "github.com/samber/lo/parallel"

lop.Times(3, func(i int) string {
    return strconv.FormatInt(int64(i), 10)
})
// []string{"0", "1", "2"}
```

### Uniq

Returns a duplicate-free version of an array, in which only the first occurrence of each element is kept. The order of result values is determined by the order they occur in the array.

```go
uniqValues := lo.Uniq([]int{1, 2, 2, 1})
// []int{1, 2}
```

[[play](https://go.dev/play/p/DTzbeXZ6iEN)]

### UniqBy

Returns a duplicate-free version of an array, in which only the first occurrence of each element is kept. The order of result values is determined by the order they occur in the array. It accepts `iteratee` which is invoked for each element in array to generate the criterion by which uniqueness is computed.

```go
uniqValues := lo.UniqBy([]int{0, 1, 2, 3, 4, 5}, func(i int) int {
    return i%3
})
// []int{0, 1, 2}
```

[[play](https://go.dev/play/p/g42Z3QSb53u)]

### GroupBy

Returns an object composed of keys generated from the results of running each element of collection through iteratee.

```go
import lo "github.com/samber/lo"

groups := lo.GroupBy([]int{0, 1, 2, 3, 4, 5}, func(i int) int {
    return i%3
})
// map[int][]int{0: []int{0, 3}, 1: []int{1, 4}, 2: []int{2, 5}}
```

[[play](https://go.dev/play/p/XnQBd_v6brd)]

Parallel processing: like `lo.GroupBy()`, but callback is called in goroutine.

```go
import lop "github.com/samber/lo/parallel"

lop.GroupBy([]int{0, 1, 2, 3, 4, 5}, func(i int) int {
    return i%3
})
// map[int][]int{0: []int{0, 3}, 1: []int{1, 4}, 2: []int{2, 5}}
```

### Chunk

Returns an array of elements split into groups the length of size. If array can't be split evenly, the final chunk will be the remaining elements.

```go
lo.Chunk([]int{0, 1, 2, 3, 4, 5}, 2)
// [][]int{{0, 1}, {2, 3}, {4, 5}}

lo.Chunk([]int{0, 1, 2, 3, 4, 5, 6}, 2)
// [][]int{{0, 1}, {2, 3}, {4, 5}, {6}}

lo.Chunk([]int{}, 2)
// [][]int{}

lo.Chunk([]int{0}, 2)
// [][]int{{0}}
```

[[play](https://go.dev/play/p/EeKl0AuTehH)]

### PartitionBy

Returns an array of elements split into groups. The order of grouped values is determined by the order they occur in collection. The grouping is generated from the results of running each element of collection through iteratee.

```go
import lo "github.com/samber/lo"

partitions := lo.PartitionBy([]int{-2, -1, 0, 1, 2, 3, 4, 5}, func(x int) string {
    if x < 0 {
        return "negative"
    } else if x%2 == 0 {
        return "even"
    }
    return "odd"
})
// [][]int{{-2, -1}, {0, 2, 4}, {1, 3, 5}}
```

[[play](https://go.dev/play/p/NfQ_nGjkgXW)]

Parallel processing: like `lo.PartitionBy()`, but callback is called in goroutine. Results are returned in the same order.

```go
import lop "github.com/samber/lo/parallel"

partitions := lop.PartitionBy([]int{-2, -1, 0, 1, 2, 3, 4, 5}, func(x int) string {
    if x < 0 {
        return "negative"
    } else if x%2 == 0 {
        return "even"
    }
    return "odd"
})
// [][]int{{-2, -1}, {0, 2, 4}, {1, 3, 5}}
```

### Flatten

Returns an array a single level deep.

```go
flat := lo.Flatten([][]int{{0, 1}, {2, 3, 4, 5}})
// []int{0, 1, 2, 3, 4, 5}
```

[[play](https://go.dev/play/p/rbp9ORaMpjw)]

### Interleave

Round-robin alternating input slices and sequentially appending value at index into result.

```go
interleaved := lo.Interleave([]int{1, 4, 7}, []int{2, 5, 8}, []int{3, 6, 9})
// []int{1, 2, 3, 4, 5, 6, 7, 8, 9}

interleaved := lo.Interleave([]int{1}, []int{2, 5, 8}, []int{3, 6}, []int{4, 7, 9, 10})
// []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
```

[[play](https://go.dev/play/p/-RJkTLQEDVt)]

### Shuffle

Returns an array of shuffled values. Uses the Fisher-Yates shuffle algorithm.

```go
randomOrder := lo.Shuffle([]int{0, 1, 2, 3, 4, 5})
// []int{1, 4, 0, 3, 5, 2}
```

[[play](https://go.dev/play/p/Qp73bnTDnc7)]

### Reverse

Reverses array so that the first element becomes the last, the second element becomes the second to last, and so on.

⚠️ This helper is **mutable**. This behavior might change in `v2.0.0`. See [#160](https://github.com/samber/lo/issues/160).

```go
reverseOrder := lo.Reverse([]int{0, 1, 2, 3, 4, 5})
// []int{5, 4, 3, 2, 1, 0}
```

[[play](https://go.dev/play/p/fhUMLvZ7vS6)]

### Fill

Fills elements of array with `initial` value.

```go
type foo struct {
  bar string
}

func (f foo) Clone() foo {
  return foo{f.bar}
}

initializedSlice := lo.Fill([]foo{foo{"a"}, foo{"a"}}, foo{"b"})
// []foo{foo{"b"}, foo{"b"}}
```

[[play](https://go.dev/play/p/VwR34GzqEub)]

### Repeat

Builds a slice with N copies of initial value.

```go
type foo struct {
  bar string
}

func (f foo) Clone() foo {
  return foo{f.bar}
}

slice := lo.Repeat(2, foo{"a"})
// []foo{foo{"a"}, foo{"a"}}
```

[[play](https://go.dev/play/p/g3uHXbmc3b6)]

### RepeatBy

Builds a slice with values returned by N calls of callback.

```go
slice := lo.RepeatBy(0, func (i int) string {
    return strconv.FormatInt(int64(math.Pow(float64(i), 2)), 10)
})
// []string{}

slice := lo.RepeatBy(5, func(i int) string {
    return strconv.FormatInt(int64(math.Pow(float64(i), 2)), 10)
})
// []string{"0", "1", "4", "9", "16"}
```

[[play](https://go.dev/play/p/ozZLCtX_hNU)]

### KeyBy

Transforms a slice or an array of structs to a map based on a pivot callback.

```go
m := lo.KeyBy([]string{"a", "aa", "aaa"}, func(str string) int {
    return len(str)
})
// map[int]string{1: "a", 2: "aa", 3: "aaa"}

type Character struct {
  dir  string
  code int
}
characters := []Character{
    {dir: "left", code: 97},
    {dir: "right", code: 100},
}
result := lo.KeyBy(characters, func(char Character) string {
    return string(rune(char.code))
})
//map[a:{dir:left code:97} d:{dir:right code:100}]
```

[[play](https://go.dev/play/p/mdaClUAT-zZ)]

### Associate (alias: SliceToMap)

Returns a map containing key-value pairs provided by transform function applied to elements of the given slice.
If any of two pairs would have the same key the last one gets added to the map.

The order of keys in returned map is not specified and is not guaranteed to be the same from the original array.

```go
in := []*foo{{baz: "apple", bar: 1}, {baz: "banana", bar: 2}}

aMap := lo.Associate(in, func (f *foo) (string, int) {
    return f.baz, f.bar
})
// map[string][int]{ "apple":1, "banana":2 }
```

[[play](https://go.dev/play/p/WHa2CfMO3Lr)]

### Drop

Drops n elements from the beginning of a slice or array.

```go
l := lo.Drop([]int{0, 1, 2, 3, 4, 5}, 2)
// []int{2, 3, 4, 5}
```

[[play](https://go.dev/play/p/JswS7vXRJP2)]

### DropRight

Drops n elements from the end of a slice or array.

```go
l := lo.DropRight([]int{0, 1, 2, 3, 4, 5}, 2)
// []int{0, 1, 2, 3}
```

[[play](https://go.dev/play/p/GG0nXkSJJa3)]

### DropWhile

Drop elements from the beginning of a slice or array while the predicate returns true.

```go
l := lo.DropWhile([]string{"a", "aa", "aaa", "aa", "aa"}, func(val string) bool {
    return len(val) <= 2
})
// []string{"aaa", "aa", "aa"}
```

[[play](https://go.dev/play/p/7gBPYw2IK16)]

### DropRightWhile

Drop elements from the end of a slice or array while the predicate returns true.

```go
l := lo.DropRightWhile([]string{"a", "aa", "aaa", "aa", "aa"}, func(val string) bool {
    return len(val) <= 2
})
// []string{"a", "aa", "aaa"}
```

[[play](https://go.dev/play/p/3-n71oEC0Hz)]

### DropByIndex

Drops elements from a slice or array by the index. A negative index will drop elements from the end of the slice.

```go
l := lo.DropByIndex([]int{0, 1, 2, 3, 4, 5}, 2, 4, -1)
// []int{0, 1, 3}
```

[[play](https://go.dev/play/p/JswS7vXRJP2)]


### Reject

The opposite of Filter, this method returns the elements of collection that predicate does not return truthy for.

```go
odd := lo.Reject([]int{1, 2, 3, 4}, func(x int, _ int) bool {
    return x%2 == 0
})
// []int{1, 3}
```

[[play](https://go.dev/play/p/YkLMODy1WEL)]

### RejectMap

The opposite of FilterMap, this method returns a slice which obtained after both filtering and mapping using the given callback function.

The callback function should return two values:
- the result of the mapping operation and
- whether the result element should be included or not.

```go
items := lo.RejectMap([]int{1, 2, 3, 4}, func(x int, _ int) (int, bool) {
    return x*10, x%2 == 0
})
// []int{10, 30}
```

### FilterReject

Mixes Filter and Reject, this method returns two slices, one for the elements of collection that predicate returns truthy for and one for the elements that predicate does not return truthy for.

```go
kept, rejected := lo.FilterReject([]int{1, 2, 3, 4}, func(x int, _ int) bool {
    return x%2 == 0
})
// []int{2, 4}
// []int{1, 3}
```

### Count

Counts the number of elements in the collection that compare equal to value.

```go
count := lo.Count([]int{1, 5, 1}, 1)
// 2
```

[[play](https://go.dev/play/p/Y3FlK54yveC)]

### CountBy

Counts the number of elements in the collection for which predicate is true.

```go
count := lo.CountBy([]int{1, 5, 1}, func(i int) bool {
    return i < 4
})
// 2
```

[[play](https://go.dev/play/p/ByQbNYQQi4X)]

### CountValues

Counts the number of each element in the collection.

```go
lo.CountValues([]int{})
// map[int]int{}

lo.CountValues([]int{1, 2})
// map[int]int{1: 1, 2: 1}

lo.CountValues([]int{1, 2, 2})
// map[int]int{1: 1, 2: 2}

lo.CountValues([]string{"foo", "bar", ""})
// map[string]int{"": 1, "foo": 1, "bar": 1}

lo.CountValues([]string{"foo", "bar", "bar"})
// map[string]int{"foo": 1, "bar": 2}
```

[[play](https://go.dev/play/p/-p-PyLT4dfy)]

### CountValuesBy

Counts the number of each element in the collection. It ss equivalent to chaining lo.Map and lo.CountValues.

```go
isEven := func(v int) bool {
    return v%2==0
}

lo.CountValuesBy([]int{}, isEven)
// map[bool]int{}

lo.CountValuesBy([]int{1, 2}, isEven)
// map[bool]int{false: 1, true: 1}

lo.CountValuesBy([]int{1, 2, 2}, isEven)
// map[bool]int{false: 1, true: 2}

length := func(v string) int {
    return len(v)
}

lo.CountValuesBy([]string{"foo", "bar", ""}, length)
// map[int]int{0: 1, 3: 2}

lo.CountValuesBy([]string{"foo", "bar", "bar"}, length)
// map[int]int{3: 3}
```

[[play](https://go.dev/play/p/2U0dG1SnOmS)]

### Subset

Returns a copy of a slice from `offset` up to `length` elements. Like `slice[start:start+length]`, but does not panic on overflow.

```go
in := []int{0, 1, 2, 3, 4}

sub := lo.Subset(in, 2, 3)
// []int{2, 3, 4}

sub := lo.Subset(in, -4, 3)
// []int{1, 2, 3}

sub := lo.Subset(in, -2, math.MaxUint)
// []int{3, 4}
```

[[play](https://go.dev/play/p/tOQu1GhFcog)]

### Slice

Returns a copy of a slice from `start` up to, but not including `end`. Like `slice[start:end]`, but does not panic on overflow.

```go
in := []int{0, 1, 2, 3, 4}

slice := lo.Slice(in, 0, 5)
// []int{0, 1, 2, 3, 4}

slice := lo.Slice(in, 2, 3)
// []int{2}

slice := lo.Slice(in, 2, 6)
// []int{2, 3, 4}

slice := lo.Slice(in, 4, 3)
// []int{}
```

[[play](https://go.dev/play/p/8XWYhfMMA1h)]

### Replace

Returns a copy of the slice with the first n non-overlapping instances of old replaced by new.

```go
in := []int{0, 1, 0, 1, 2, 3, 0}

slice := lo.Replace(in, 0, 42, 1)
// []int{42, 1, 0, 1, 2, 3, 0}

slice := lo.Replace(in, -1, 42, 1)
// []int{0, 1, 0, 1, 2, 3, 0}

slice := lo.Replace(in, 0, 42, 2)
// []int{42, 1, 42, 1, 2, 3, 0}

slice := lo.Replace(in, 0, 42, -1)
// []int{42, 1, 42, 1, 2, 3, 42}
```

[[play](https://go.dev/play/p/XfPzmf9gql6)]

### ReplaceAll

Returns a copy of the slice with all non-overlapping instances of old replaced by new.

```go
in := []int{0, 1, 0, 1, 2, 3, 0}

slice := lo.ReplaceAll(in, 0, 42)
// []int{42, 1, 42, 1, 2, 3, 42}

slice := lo.ReplaceAll(in, -1, 42)
// []int{0, 1, 0, 1, 2, 3, 0}
```

[[play](https://go.dev/play/p/a9xZFUHfYcV)]

### Compact

Returns a slice of all non-zero elements.

```go
in := []string{"", "foo", "", "bar", ""}

slice := lo.Compact(in)
// []string{"foo", "bar"}
```

[[play](https://go.dev/play/p/tXiy-iK6PAc)]

### IsSorted

Checks if a slice is sorted.

```go
slice := lo.IsSorted([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
// true
```

[[play](https://go.dev/play/p/mc3qR-t4mcx)]

### IsSortedByKey

Checks if a slice is sorted by iteratee.

```go
slice := lo.IsSortedByKey([]string{"a", "bb", "ccc"}, func(s string) int {
    return len(s)
})
// true
```

[[play](https://go.dev/play/p/wiG6XyBBu49)]

### Splice

Splice inserts multiple elements at index i. A negative index counts back from the end of the slice. The helper is protected against overflow errors.

```go
result := lo.Splice([]string{"a", "b"}, 1, "1", "2")
// []string{"a", "1", "2", "b"}

// negative
result = lo.Splice([]string{"a", "b"}, -1, "1", "2")
// []string{"a", "1", "2", "b"}

// overflow
result = lo.Splice([]string{"a", "b"}, 42, "1", "2")
// []string{"a", "b", "1", "2"}
```

[[play](https://go.dev/play/p/G5_GhkeSUBA)]

### Keys

Creates a slice of the map keys.

Use the UniqKeys variant to deduplicate common keys.

```go
keys := lo.Keys(map[string]int{"foo": 1, "bar": 2})
// []string{"foo", "bar"}

keys := lo.Keys(map[string]int{"foo": 1, "bar": 2}, map[string]int{"baz": 3})
// []string{"foo", "bar", "baz"}

keys := lo.Keys(map[string]int{"foo": 1, "bar": 2}, map[string]int{"bar": 3})
// []string{"foo", "bar", "bar"}
```

[[play](https://go.dev/play/p/Uu11fHASqrU)]

### UniqKeys

Creates an array of unique map keys. 

```go
keys := lo.Keys(map[string]int{"foo": 1, "bar": 2}, map[string]int{"baz": 3})
// []string{"foo", "bar", "baz"}

keys := lo.Keys(map[string]int{"foo": 1, "bar": 2}, map[string]int{"bar": 3})
// []string{"foo", "bar"}
```

[[play](https://go.dev/play/p/TPKAb6ILdHk)]

### HasKey

Returns whether the given key exists.

```go
exists := lo.HasKey(map[string]int{"foo": 1, "bar": 2}, "foo")
// true

exists := lo.HasKey(map[string]int{"foo": 1, "bar": 2}, "baz")
// false
```

[[play](https://go.dev/play/p/aVwubIvECqS)]

### Values

Creates an array of the map values.

Use the UniqValues variant to deduplicate common values.

```go
values := lo.Values(map[string]int{"foo": 1, "bar": 2})
// []int{1, 2}

values := lo.Values(map[string]int{"foo": 1, "bar": 2}, map[string]int{"baz": 3})
// []int{1, 2, 3}

values := lo.Values(map[string]int{"foo": 1, "bar": 2}, map[string]int{"bar": 2})
// []int{1, 2, 2}
```

[[play](https://go.dev/play/p/nnRTQkzQfF6)]

### UniqValues

Creates an array of unique map values.

```go
values := lo.UniqValues(map[string]int{"foo": 1, "bar": 2})
// []int{1, 2}

values := lo.UniqValues(map[string]int{"foo": 1, "bar": 2}, map[string]int{"baz": 3})
// []int{1, 2, 3}

values := lo.UniqValues(map[string]int{"foo": 1, "bar": 2}, map[string]int{"bar": 2})
// []int{1, 2}
```

[[play](https://go.dev/play/p/nf6bXMh7rM3)]

### ValueOr

Returns the value of the given key or the fallback value if the key is not present.

```go
value := lo.ValueOr(map[string]int{"foo": 1, "bar": 2}, "foo", 42)
// 1

value := lo.ValueOr(map[string]int{"foo": 1, "bar": 2}, "baz", 42)
// 42
```

[[play](https://go.dev/play/p/bAq9mHErB4V)]

### PickBy

Returns same map type filtered by given predicate.

```go
m := lo.PickBy(map[string]int{"foo": 1, "bar": 2, "baz": 3}, func(key string, value int) bool {
    return value%2 == 1
})
// map[string]int{"foo": 1, "baz": 3}
```

[[play](https://go.dev/play/p/kdg8GR_QMmf)]

### PickByKeys

Returns same map type filtered by given keys.

```go
m := lo.PickByKeys(map[string]int{"foo": 1, "bar": 2, "baz": 3}, []string{"foo", "baz"})
// map[string]int{"foo": 1, "baz": 3}
```

[[play](https://go.dev/play/p/R1imbuci9qU)]

### PickByValues

Returns same map type filtered by given values.

```go
m := lo.PickByValues(map[string]int{"foo": 1, "bar": 2, "baz": 3}, []int{1, 3})
// map[string]int{"foo": 1, "baz": 3}
```

[[play](https://go.dev/play/p/1zdzSvbfsJc)]

### OmitBy

Returns same map type filtered by given predicate.

```go
m := lo.OmitBy(map[string]int{"foo": 1, "bar": 2, "baz": 3}, func(key string, value int) bool {
    return value%2 == 1
})
// map[string]int{"bar": 2}
```

[[play](https://go.dev/play/p/EtBsR43bdsd)]

### OmitByKeys

Returns same map type filtered by given keys.

```go
m := lo.OmitByKeys(map[string]int{"foo": 1, "bar": 2, "baz": 3}, []string{"foo", "baz"})
// map[string]int{"bar": 2}
```

[[play](https://go.dev/play/p/t1QjCrs-ysk)]

### OmitByValues

Returns same map type filtered by given values.

```go
m := lo.OmitByValues(map[string]int{"foo": 1, "bar": 2, "baz": 3}, []int{1, 3})
// map[string]int{"bar": 2}
```

[[play](https://go.dev/play/p/9UYZi-hrs8j)]

### Entries (alias: ToPairs)

Transforms a map into array of key/value pairs.

```go
entries := lo.Entries(map[string]int{"foo": 1, "bar": 2})
// []lo.Entry[string, int]{
//     {
//         Key: "foo",
//         Value: 1,
//     },
//     {
//         Key: "bar",
//         Value: 2,
//     },
// }
```

[[play](https://go.dev/play/p/3Dhgx46gawJ)]

### FromEntries (alias: FromPairs)

Transforms an array of key/value pairs into a map.

```go
m := lo.FromEntries([]lo.Entry[string, int]{
    {
        Key: "foo",
        Value: 1,
    },
    {
        Key: "bar",
        Value: 2,
    },
})
// map[string]int{"foo": 1, "bar": 2}
```

[[play](https://go.dev/play/p/oIr5KHFGCEN)]

### Invert

Creates a map composed of the inverted keys and values. If map contains duplicate values, subsequent values overwrite property assignments of previous values.

```go
m1 := lo.Invert(map[string]int{"a": 1, "b": 2})
// map[int]string{1: "a", 2: "b"}

m2 := lo.Invert(map[string]int{"a": 1, "b": 2, "c": 1})
// map[int]string{1: "c", 2: "b"}
```

[[play](https://go.dev/play/p/rFQ4rak6iA1)]

### Assign

Merges multiple maps from left to right.

```go
mergedMaps := lo.Assign(
    map[string]int{"a": 1, "b": 2},
    map[string]int{"b": 3, "c": 4},
)
// map[string]int{"a": 1, "b": 3, "c": 4}
```

[[play](https://go.dev/play/p/VhwfJOyxf5o)]

### MapKeys

Manipulates a map keys and transforms it to a map of another type.

```go
m2 := lo.MapKeys(map[int]int{1: 1, 2: 2, 3: 3, 4: 4}, func(_ int, v int) string {
    return strconv.FormatInt(int64(v), 10)
})
// map[string]int{"1": 1, "2": 2, "3": 3, "4": 4}
```

[[play](https://go.dev/play/p/9_4WPIqOetJ)]

### MapValues

Manipulates a map values and transforms it to a map of another type.

```go
m1 := map[int]int64{1: 1, 2: 2, 3: 3}

m2 := lo.MapValues(m1, func(x int64, _ int) string {
    return strconv.FormatInt(x, 10)
})
// map[int]string{1: "1", 2: "2", 3: "3"}
```

[[play](https://go.dev/play/p/T_8xAfvcf0W)]

### MapEntries

Manipulates a map entries and transforms it to a map of another type.

```go
in := map[string]int{"foo": 1, "bar": 2}

out := lo.MapEntries(in, func(k string, v int) (int, string) {
    return v,k
})
// map[int]string{1: "foo", 2: "bar"}
```

[[play](https://go.dev/play/p/VuvNQzxKimT)]

### MapToSlice

Transforms a map into a slice based on specific iteratee.

```go
m := map[int]int64{1: 4, 2: 5, 3: 6}

s := lo.MapToSlice(m, func(k int, v int64) string {
    return fmt.Sprintf("%d_%d", k, v)
})
// []string{"1_4", "2_5", "3_6"}
```

[[play](https://go.dev/play/p/ZuiCZpDt6LD)]

### Range / RangeFrom / RangeWithSteps

Creates an array of numbers (positive and/or negative) progressing from start up to, but not including end.

```go
result := lo.Range(4)
// [0, 1, 2, 3]

result := lo.Range(-4)
// [0, -1, -2, -3]

result := lo.RangeFrom(1, 5)
// [1, 2, 3, 4, 5]

result := lo.RangeFrom[float64](1.0, 5)
// [1.0, 2.0, 3.0, 4.0, 5.0]

result := lo.RangeWithSteps(0, 20, 5)
// [0, 5, 10, 15]

result := lo.RangeWithSteps[float32](-1.0, -4.0, -1.0)
// [-1.0, -2.0, -3.0]

result := lo.RangeWithSteps(1, 4, -1)
// []

result := lo.Range(0)
// []
```

[[play](https://go.dev/play/p/0r6VimXAi9H)]

### Clamp

Clamps number within the inclusive lower and upper bounds.

```go
r1 := lo.Clamp(0, -10, 10)
// 0

r2 := lo.Clamp(-42, -10, 10)
// -10

r3 := lo.Clamp(42, -10, 10)
// 10
```

[[play](https://go.dev/play/p/RU4lJNC2hlI)]

### Sum

Sums the values in a collection.

If collection is empty 0 is returned.

```go
list := []int{1, 2, 3, 4, 5}
sum := lo.Sum(list)
// 15
```

[[play](https://go.dev/play/p/upfeJVqs4Bt)]

### SumBy

Summarizes the values in a collection using the given return value from the iteration function.

If collection is empty 0 is returned.

```go
strings := []string{"foo", "bar"}
sum := lo.SumBy(strings, func(item string) int {
    return len(item)
})
// 6
```

[[play](https://go.dev/play/p/Dz_a_7jN_ca)]

### Mean

Calculates the mean of a collection of numbers.

If collection is empty 0 is returned.

```go
mean := lo.Mean([]int{2, 3, 4, 5})
// 3

mean := lo.Mean([]float64{2, 3, 4, 5})
// 3.5

mean := lo.Mean([]float64{})
// 0
```

### MeanBy

Calculates the mean of a collection of numbers using the given return value from the iteration function.

If collection is empty 0 is returned.

```go
list := []string{"aa", "bbb", "cccc", "ddddd"}
mapper := func(item string) float64 {
    return float64(len(item))
}

mean := lo.MeanBy(list, mapper)
// 3.5

mean := lo.MeanBy([]float64{}, mapper)
// 0
```

### RandomString

Returns a random string of the specified length and made of the specified charset.

```go
str := lo.RandomString(5, lo.LettersCharset)
// example: "eIGbt"
```

[[play](https://go.dev/play/p/rRseOQVVum4)]

### Substring

Return part of a string.

```go
sub := lo.Substring("hello", 2, 3)
// "llo"

sub := lo.Substring("hello", -4, 3)
// "ell"

sub := lo.Substring("hello", -2, math.MaxUint)
// "lo"
```

[[play](https://go.dev/play/p/TQlxQi82Lu1)]

### ChunkString

Returns an array of strings split into groups the length of size. If array can't be split evenly, the final chunk will be the remaining elements.

```go
lo.ChunkString("123456", 2)
// []string{"12", "34", "56"}

lo.ChunkString("1234567", 2)
// []string{"12", "34", "56", "7"}

lo.ChunkString("", 2)
// []string{""}

lo.ChunkString("1", 2)
// []string{"1"}
```

[[play](https://go.dev/play/p/__FLTuJVz54)]

### RuneLength

An alias to utf8.RuneCountInString which returns the number of runes in string.

```go
sub := lo.RuneLength("hellô")
// 5

sub := len("hellô")
// 6
```

[[play](https://go.dev/play/p/tuhgW_lWY8l)]

### PascalCase

Converts string to pascal case.

```go
str := lo.PascalCase("hello_world")
// HelloWorld
```

[[play](https://go.dev/play/p/iZkdeLP9oiB)]

### CamelCase

Converts string to camel case.

```go
str := lo.CamelCase("hello_world")
// helloWorld
```

[[play](https://go.dev/play/p/dtyFB58MBRp)]

### KebabCase

Converts string to kebab case.

```go
str := lo.KebabCase("helloWorld")
// hello-world
```

[[play](https://go.dev/play/p/2YTuPafwECA)]

### SnakeCase

Converts string to snake case.

```go
str := lo.SnakeCase("HelloWorld")
// hello_world
```

[[play](https://go.dev/play/p/QVKJG9nOnDg)]

### Words

Splits string into an array of its words.

```go
str := lo.Words("helloWorld")
// []string{"hello", "world"}
```

[[play](https://go.dev/play/p/2P4zhqqq61g)]

### Capitalize

Converts the first character of string to upper case and the remaining to lower case.

```go
str := lo.Capitalize("heLLO")
// Hello
```

### Elipse

Truncates a string to a specified length and appends an ellipsis if truncated.

```go
str := lo.Elipse("Lorem Ipsum", 5)
// Lo...

str := lo.Elipse("Lorem Ipsum", 100)
// Lorem Ipsum

str := lo.Elipse("Lorem Ipsum", 3)
// ...
```

### T2 -> T9

Creates a tuple from a list of values.

```go
tuple1 := lo.T2("x", 1)
// Tuple2[string, int]{A: "x", B: 1}

func example() (string, int) { return "y", 2 }
tuple2 := lo.T2(example())
// Tuple2[string, int]{A: "y", B: 2}
```

[[play](https://go.dev/play/p/IllL3ZO4BQm)]

### Unpack2 -> Unpack9

Returns values contained in tuple.

```go
r1, r2 := lo.Unpack2(lo.Tuple2[string, int]{"a", 1})
// "a", 1
```

Unpack is also available as a method of TupleX.

```go
tuple2 := lo.T2("a", 1)
a, b := tuple2.Unpack()
// "a", 1
```

[[play](https://go.dev/play/p/xVP_k0kJ96W)]

### Zip2 -> Zip9

Zip creates a slice of grouped elements, the first of which contains the first elements of the given arrays, the second of which contains the second elements of the given arrays, and so on.

When collections have different size, the Tuple attributes are filled with zero value.

```go
tuples := lo.Zip2([]string{"a", "b"}, []int{1, 2})
// []Tuple2[string, int]{{A: "a", B: 1}, {A: "b", B: 2}}
```

[[play](https://go.dev/play/p/jujaA6GaJTp)]

### ZipBy2 -> ZipBy9

ZipBy creates a slice of transformed elements, the first of which contains the first elements of the given arrays, the second of which contains the second elements of the given arrays, and so on.

When collections have different size, the Tuple attributes are filled with zero value.

```go
items := lo.ZipBy2([]string{"a", "b"}, []int{1, 2}, func(a string, b int) string {
    return fmt.Sprintf("%s-%d", a, b)
})
// []string{"a-1", "b-2"}
```

### Unzip2 -> Unzip9

Unzip accepts an array of grouped elements and creates an array regrouping the elements to their pre-zip configuration.

```go
a, b := lo.Unzip2([]Tuple2[string, int]{{A: "a", B: 1}, {A: "b", B: 2}})
// []string{"a", "b"}
// []int{1, 2}
```

[[play](https://go.dev/play/p/ciHugugvaAW)]

### UnzipBy2 -> UnzipBy9

UnzipBy2 iterates over a collection and creates an array regrouping the elements to their pre-zip configuration.

```go
a, b := lo.UnzipBy2([]string{"hello", "john", "doe"}, func(str string) (string, int) {
    return str, len(str)
})
// []string{"hello", "john", "doe"}
// []int{5, 4, 3}
```

### Duration

Returns the time taken to execute a function.

```go
duration := lo.Duration(func() {
    // very long job
})
// 3s
```

### Duration0 -> Duration10

Returns the time taken to execute a function.

```go
duration := lo.Duration0(func() {
    // very long job
})
// 3s

err, duration := lo.Duration1(func() error {
    // very long job
    return fmt.Errorf("an error")
})
// an error
// 3s

str, nbr, err, duration := lo.Duration3(func() (string, int, error) {
    // very long job
    return "hello", 42, nil
})
// hello
// 42
// nil
// 3s
```

### ChannelDispatcher

Distributes messages from input channels into N child channels. Close events are propagated to children.

Underlying channels can have a fixed buffer capacity or be unbuffered when cap is 0.

```go
ch := make(chan int, 42)
for i := 0; i <= 10; i++ {
    ch <- i
}

children := lo.ChannelDispatcher(ch, 5, 10, DispatchingStrategyRoundRobin[int])
// []<-chan int{...}

consumer := func(c <-chan int) {
    for {
        msg, ok := <-c
        if !ok {
            println("closed")

            break
        }

        println(msg)
    }
}

for i := range children {
    go consumer(children[i])
}
```

Many distributions strategies are available:

- [lo.DispatchingStrategyRoundRobin](./channel.go): Distributes messages in a rotating sequential manner.
- [lo.DispatchingStrategyRandom](./channel.go): Distributes messages in a random manner.
- [lo.DispatchingStrategyWeightedRandom](./channel.go): Distributes messages in a weighted manner.
- [lo.DispatchingStrategyFirst](./channel.go): Distributes messages in the first non-full channel.
- [lo.DispatchingStrategyLeast](./channel.go): Distributes messages in the emptiest channel.
- [lo.DispatchingStrategyMost](./channel.go): Distributes to the fullest channel.

Some strategies bring fallback, in order to favor non-blocking behaviors. See implementations.

For custom strategies, just implement the `lo.DispatchingStrategy` prototype:

```go
type DispatchingStrategy[T any] func(message T, messageIndex uint64, channels []<-chan T) int
```

Eg:

```go
type Message struct {
    TenantID uuid.UUID
}

func hash(id uuid.UUID) int {
    h := fnv.New32a()
    h.Write([]byte(id.String()))
    return int(h.Sum32())
}

// Routes messages per TenantID.
customStrategy := func(message string, messageIndex uint64, channels []<-chan string) int {
    destination := hash(message) % len(channels)

    // check if channel is full
    if len(channels[destination]) < cap(channels[destination]) {
        return destination
    }

    // fallback when child channel is full
    return utils.DispatchingStrategyRoundRobin(message, uint64(destination), channels)
}

children := lo.ChannelDispatcher(ch, 5, 10, customStrategy)
...
```

### SliceToChannel

Returns a read-only channels of collection elements. Channel is closed after last element. Channel capacity can be customized.

```go
list := []int{1, 2, 3, 4, 5}

for v := range lo.SliceToChannel(2, list) {
    println(v)
}
// prints 1, then 2, then 3, then 4, then 5
```

### ChannelToSlice

Returns a slice built from channels items. Blocks until channel closes.

```go
list := []int{1, 2, 3, 4, 5}
ch := lo.SliceToChannel(2, list)

items := ChannelToSlice(ch)
// []int{1, 2, 3, 4, 5}
```

### Generator

Implements the generator design pattern. Channel is closed after last element. Channel capacity can be customized.

```go
generator := func(yield func(int)) {
    yield(1)
    yield(2)
    yield(3)
}

for v := range lo.Generator(2, generator) {
    println(v)
}
// prints 1, then 2, then 3
```

### Buffer

Creates a slice of n elements from a channel. Returns the slice, the slice length, the read time and the channel status (opened/closed).

```go
ch := lo.SliceToChannel(2, []int{1, 2, 3, 4, 5})

items1, length1, duration1, ok1 := lo.Buffer(ch, 3)
// []int{1, 2, 3}, 3, 0s, true
items2, length2, duration2, ok2 := lo.Buffer(ch, 3)
// []int{4, 5}, 2, 0s, false
```

Example: RabbitMQ consumer 👇

```go
ch := readFromQueue()

for {
    // read 1k items
    items, length, _, ok := lo.Buffer(ch, 1000)

    // do batching stuff

    if !ok {
        break
    }
}
```

### BufferWithTimeout

Creates a slice of n elements from a channel, with timeout. Returns the slice, the slice length, the read time and the channel status (opened/closed).

```go
generator := func(yield func(int)) {
    for i := 0; i < 5; i++ {
        yield(i)
        time.Sleep(35*time.Millisecond)
    }
}

ch := lo.Generator(0, generator)

items1, length1, duration1, ok1 := lo.BufferWithTimeout(ch, 3, 100*time.Millisecond)
// []int{1, 2}, 2, 100ms, true
items2, length2, duration2, ok2 := lo.BufferWithTimeout(ch, 3, 100*time.Millisecond)
// []int{3, 4, 5}, 3, 75ms, true
items3, length3, duration2, ok3 := lo.BufferWithTimeout(ch, 3, 100*time.Millisecond)
// []int{}, 0, 10ms, false
```

Example: RabbitMQ consumer 👇

```go
ch := readFromQueue()

for {
    // read 1k items
    // wait up to 1 second
    items, length, _, ok := lo.BufferWithTimeout(ch, 1000, 1*time.Second)

    // do batching stuff

    if !ok {
        break
    }
}
```

Example: Multithreaded RabbitMQ consumer 👇

```go
ch := readFromQueue()

// 5 workers
// prefetch 1k messages per worker
children := lo.ChannelDispatcher(ch, 5, 1000, lo.DispatchingStrategyFirst[int])

consumer := func(c <-chan int) {
    for {
        // read 1k items
        // wait up to 1 second
        items, length, _, ok := lo.BufferWithTimeout(ch, 1000, 1*time.Second)

        // do batching stuff

        if !ok {
            break
        }
    }
}

for i := range children {
    go consumer(children[i])
}
```

### FanIn

Merge messages from multiple input channels into a single buffered channel. Output messages has no priority. When all upstream channels reach EOF, downstream channel closes.

```go
stream1 := make(chan int, 42)
stream2 := make(chan int, 42)
stream3 := make(chan int, 42)

all := lo.FanIn(100, stream1, stream2, stream3)
// <-chan int
```

### FanOut

Broadcasts all the upstream messages to multiple downstream channels. When upstream channel reach EOF, downstream channels close. If any downstream channels is full, broadcasting is paused.

```go
stream := make(chan int, 42)

all := lo.FanOut(5, 100, stream)
// [5]<-chan int
```

### Contains

Returns true if an element is present in a collection.

```go
present := lo.Contains([]int{0, 1, 2, 3, 4, 5}, 5)
// true
```

### ContainsBy

Returns true if the predicate function returns `true`.

```go
present := lo.ContainsBy([]int{0, 1, 2, 3, 4, 5}, func(x int) bool {
    return x == 3
})
// true
```

### Every

Returns true if all elements of a subset are contained into a collection or if the subset is empty.

```go
ok := lo.Every([]int{0, 1, 2, 3, 4, 5}, []int{0, 2})
// true

ok := lo.Every([]int{0, 1, 2, 3, 4, 5}, []int{0, 6})
// false
```

### EveryBy

Returns true if the predicate returns true for all of the elements in the collection or if the collection is empty.

```go
b := EveryBy([]int{1, 2, 3, 4}, func(x int) bool {
    return x < 5
})
// true
```

### Some

Returns true if at least 1 element of a subset is contained into a collection.
If the subset is empty Some returns false.

```go
ok := lo.Some([]int{0, 1, 2, 3, 4, 5}, []int{0, 2})
// true

ok := lo.Some([]int{0, 1, 2, 3, 4, 5}, []int{-1, 6})
// false
```

### SomeBy

Returns true if the predicate returns true for any of the elements in the collection.
If the collection is empty SomeBy returns false.

```go
b := SomeBy([]int{1, 2, 3, 4}, func(x int) bool {
    return x < 3
})
// true
```

### None

Returns true if no element of a subset are contained into a collection or if the subset is empty.

```go
b := None([]int{0, 1, 2, 3, 4, 5}, []int{0, 2})
// false
b := None([]int{0, 1, 2, 3, 4, 5}, []int{-1, 6})
// true
```

### NoneBy

Returns true if the predicate returns true for none of the elements in the collection or if the collection is empty.

```go
b := NoneBy([]int{1, 2, 3, 4}, func(x int) bool {
    return x < 0
})
// true
```

### Intersect

Returns the intersection between two collections.

```go
result1 := lo.Intersect([]int{0, 1, 2, 3, 4, 5}, []int{0, 2})
// []int{0, 2}

result2 := lo.Intersect([]int{0, 1, 2, 3, 4, 5}, []int{0, 6})
// []int{0}

result3 := lo.Intersect([]int{0, 1, 2, 3, 4, 5}, []int{-1, 6})
// []int{}
```

### Difference

Returns the difference between two collections.

- The first value is the collection of element absent of list2.
- The second value is the collection of element absent of list1.

```go
left, right := lo.Difference([]int{0, 1, 2, 3, 4, 5}, []int{0, 2, 6})
// []int{1, 3, 4, 5}, []int{6}

left, right := lo.Difference([]int{0, 1, 2, 3, 4, 5}, []int{0, 1, 2, 3, 4, 5})
// []int{}, []int{}
```

### Union

Returns all distinct elements from given collections. Result will not change the order of elements relatively.

```go
union := lo.Union([]int{0, 1, 2, 3, 4, 5}, []int{0, 2}, []int{0, 10})
// []int{0, 1, 2, 3, 4, 5, 10}
```

### Without

Returns slice excluding all given values.

```go
subset := lo.Without([]int{0, 2, 10}, 2)
// []int{0, 10}

subset := lo.Without([]int{0, 2, 10}, 0, 1, 2, 3, 4, 5)
// []int{10}
```

### WithoutEmpty

Returns slice excluding empty values.

```go
subset := lo.WithoutEmpty([]int{0, 2, 10})
// []int{2, 10}
```

### IndexOf

Returns the index at which the first occurrence of a value is found in an array or return -1 if the value cannot be found.

```go
found := lo.IndexOf([]int{0, 1, 2, 1, 2, 3}, 2)
// 2

notFound := lo.IndexOf([]int{0, 1, 2, 1, 2, 3}, 6)
// -1
```

### LastIndexOf

Returns the index at which the last occurrence of a value is found in an array or return -1 if the value cannot be found.

```go
found := lo.LastIndexOf([]int{0, 1, 2, 1, 2, 3}, 2)
// 4

notFound := lo.LastIndexOf([]int{0, 1, 2, 1, 2, 3}, 6)
// -1
```

### Find

Search an element in a slice based on a predicate. It returns element and true if element was found.

```go
str, ok := lo.Find([]string{"a", "b", "c", "d"}, func(i string) bool {
    return i == "b"
})
// "b", true

str, ok := lo.Find([]string{"foobar"}, func(i string) bool {
    return i == "b"
})
// "", false
```

### FindIndexOf

FindIndexOf searches an element in a slice based on a predicate and returns the index and true. It returns -1 and false if the element is not found.

```go
str, index, ok := lo.FindIndexOf([]string{"a", "b", "a", "b"}, func(i string) bool {
    return i == "b"
})
// "b", 1, true

str, index, ok := lo.FindIndexOf([]string{"foobar"}, func(i string) bool {
    return i == "b"
})
// "", -1, false
```

### FindLastIndexOf

FindLastIndexOf searches an element in a slice based on a predicate and returns the index and true. It returns -1 and false if the element is not found.

```go
str, index, ok := lo.FindLastIndexOf([]string{"a", "b", "a", "b"}, func(i string) bool {
    return i == "b"
})
// "b", 4, true

str, index, ok := lo.FindLastIndexOf([]string{"foobar"}, func(i string) bool {
    return i == "b"
})
// "", -1, false
```

### FindOrElse

Search an element in a slice based on a predicate. It returns the element if found or a given fallback value otherwise.

```go
str := lo.FindOrElse([]string{"a", "b", "c", "d"}, "x", func(i string) bool {
    return i == "b"
})
// "b"

str := lo.FindOrElse([]string{"foobar"}, "x", func(i string) bool {
    return i == "b"
})
// "x"
```

### FindKey

Returns the key of the first value matching.

```go
result1, ok1 := lo.FindKey(map[string]int{"foo": 1, "bar": 2, "baz": 3}, 2)
// "bar", true

result2, ok2 := lo.FindKey(map[string]int{"foo": 1, "bar": 2, "baz": 3}, 42)
// "", false

type test struct {
    foobar string
}
result3, ok3 := lo.FindKey(map[string]test{"foo": test{"foo"}, "bar": test{"bar"}, "baz": test{"baz"}}, test{"foo"})
// "foo", true
```

### FindKeyBy

Returns the key of the first element predicate returns truthy for.

```go
result1, ok1 := lo.FindKeyBy(map[string]int{"foo": 1, "bar": 2, "baz": 3}, func(k string, v int) bool {
    return k == "foo"
})
// "foo", true

result2, ok2 := lo.FindKeyBy(map[string]int{"foo": 1, "bar": 2, "baz": 3}, func(k string, v int) bool {
    return false
})
// "", false
```

### FindUniques

Returns a slice with all the unique elements of the collection. The order of result values is determined by the order they occur in the array.

```go
uniqueValues := lo.FindUniques([]int{1, 2, 2, 1, 2, 3})
// []int{3}
```

### FindUniquesBy

Returns a slice with all the unique elements of the collection. The order of result values is determined by the order they occur in the array. It accepts `iteratee` which is invoked for each element in array to generate the criterion by which uniqueness is computed.

```go
uniqueValues := lo.FindUniquesBy([]int{3, 4, 5, 6, 7}, func(i int) int {
    return i%3
})
// []int{5}
```

### FindDuplicates

Returns a slice with the first occurrence of each duplicated elements of the collection. The order of result values is determined by the order they occur in the array.

```go
duplicatedValues := lo.FindDuplicates([]int{1, 2, 2, 1, 2, 3})
// []int{1, 2}
```

### FindDuplicatesBy

Returns a slice with the first occurrence of each duplicated elements of the collection. The order of result values is determined by the order they occur in the array. It accepts `iteratee` which is invoked for each element in array to generate the criterion by which uniqueness is computed.

```go
duplicatedValues := lo.FindDuplicatesBy([]int{3, 4, 5, 6, 7}, func(i int) int {
    return i%3
})
// []int{3, 4}
```

### Min

Search the minimum value of a collection.

Returns zero value when the collection is empty.

```go
min := lo.Min([]int{1, 2, 3})
// 1

min := lo.Min([]int{})
// 0

min := lo.Min([]time.Duration{time.Second, time.Hour})
// 1s
```

### MinBy

Search the minimum value of a collection using the given comparison function.

If several values of the collection are equal to the smallest value, returns the first such value.

Returns zero value when the collection is empty.

```go
min := lo.MinBy([]string{"s1", "string2", "s3"}, func(item string, min string) bool {
    return len(item) < len(min)
})
// "s1"

min := lo.MinBy([]string{}, func(item string, min string) bool {
    return len(item) < len(min)
})
// ""
```

### Earliest

Search the minimum time.Time of a collection.

Returns zero value when the collection is empty.

```go
earliest := lo.Earliest(time.Now(), time.Time{})
// 0001-01-01 00:00:00 +0000 UTC
```

### EarliestBy

Search the minimum time.Time of a collection using the given iteratee function.

Returns zero value when the collection is empty.

```go
type foo struct {
    bar time.Time
}

earliest := lo.EarliestBy([]foo{{time.Now()}, {}}, func(i foo) time.Time {
    return i.bar
})
// {bar:{2023-04-01 01:02:03 +0000 UTC}}
```

### Max

Search the maximum value of a collection.

Returns zero value when the collection is empty.

```go
max := lo.Max([]int{1, 2, 3})
// 3

max := lo.Max([]int{})
// 0

max := lo.Max([]time.Duration{time.Second, time.Hour})
// 1h
```

### MaxBy

Search the maximum value of a collection using the given comparison function.

If several values of the collection are equal to the greatest value, returns the first such value.

Returns zero value when the collection is empty.

```go
max := lo.MaxBy([]string{"string1", "s2", "string3"}, func(item string, max string) bool {
    return len(item) > len(max)
})
// "string1"

max := lo.MaxBy([]string{}, func(item string, max string) bool {
    return len(item) > len(max)
})
// ""
```

### Latest

Search the maximum time.Time of a collection.

Returns zero value when the collection is empty.

```go
latest := lo.Latest([]time.Time{time.Now(), time.Time{}})
// 2023-04-01 01:02:03 +0000 UTC
```

### LatestBy

Search the maximum time.Time of a collection using the given iteratee function.

Returns zero value when the collection is empty.

```go
type foo struct {
    bar time.Time
}

latest := lo.LatestBy([]foo{{time.Now()}, {}}, func(i foo) time.Time {
    return i.bar
})
// {bar:{2023-04-01 01:02:03 +0000 UTC}}
```

### First

Returns the first element of a collection and check for availability of the first element.

```go
first, ok := lo.First([]int{1, 2, 3})
// 1, true

first, ok := lo.First([]int{})
// 0, false
```

### FirstOrEmpty

Returns the first element of a collection or zero value if empty.

```go
first := lo.FirstOrEmpty([]int{1, 2, 3})
// 1

first := lo.FirstOrEmpty([]int{})
// 0
```
### FirstOr

Returns the first element of a collection or the fallback value if empty.

```go
first := lo.FirstOr([]int{1, 2, 3}, 245)
// 1

first := lo.FirstOr([]int{}, 31)
// 31
```

### Last

Returns the last element of a collection or error if empty.

```go
last, ok := lo.Last([]int{1, 2, 3})
// 3
// true

last, ok := lo.Last([]int{})
// 0
// false
```

### LastOrEmpty

Returns the first element of a collection or zero value if empty.

```go
last := lo.LastOrEmpty([]int{1, 2, 3})
// 3

last := lo.LastOrEmpty([]int{})
// 0
```
### LastOr

Returns the first element of a collection or the fallback value if empty.

```go
last := lo.LastOr([]int{1, 2, 3}, 245)
// 3

last := lo.LastOr([]int{}, 31)
// 31
```

### Nth

Returns the element at index `nth` of collection. If `nth` is negative, the nth element from the end is returned. An error is returned when nth is out of slice bounds.

```go
nth, err := lo.Nth([]int{0, 1, 2, 3}, 2)
// 2

nth, err := lo.Nth([]int{0, 1, 2, 3}, -2)
// 2
```

### Sample

Returns a random item from collection.

```go
lo.Sample([]string{"a", "b", "c"})
// a random string from []string{"a", "b", "c"}

lo.Sample([]string{})
// ""
```

### Samples

Returns N random unique items from collection.

```go
lo.Samples([]string{"a", "b", "c"}, 3)
// []string{"a", "b", "c"} in random order
```

### Ternary

A 1 line if/else statement.

```go
result := lo.Ternary(true, "a", "b")
// "a"

result := lo.Ternary(false, "a", "b")
// "b"
```

[[play](https://go.dev/play/p/t-D7WBL44h2)]

### TernaryF

A 1 line if/else statement whose options are functions.

```go
result := lo.TernaryF(true, func() string { return "a" }, func() string { return "b" })
// "a"

result := lo.TernaryF(false, func() string { return "a" }, func() string { return "b" })
// "b"
```

Useful to avoid nil-pointer dereferencing in initializations, or avoid running unnecessary code

```go
var s *string

someStr := TernaryF(s == nil, func() string { return uuid.New().String() }, func() string { return *s })
// ef782193-c30c-4e2e-a7ae-f8ab5e125e02
```

[[play](https://go.dev/play/p/AO4VW20JoqM)]

### If / ElseIf / Else

```go
result := lo.If(true, 1).
    ElseIf(false, 2).
    Else(3)
// 1

result := lo.If(false, 1).
    ElseIf(true, 2).
    Else(3)
// 2

result := lo.If(false, 1).
    ElseIf(false, 2).
    Else(3)
// 3
```

Using callbacks:

```go
result := lo.IfF(true, func () int {
        return 1
    }).
    ElseIfF(false, func () int {
        return 2
    }).
    ElseF(func () int {
        return 3
    })
// 1
```

Mixed:

```go
result := lo.IfF(true, func () int {
        return 1
    }).
    Else(42)
// 1
```

[[play](https://go.dev/play/p/WSw3ApMxhyW)]

### Switch / Case / Default

```go
result := lo.Switch(1).
    Case(1, "1").
    Case(2, "2").
    Default("3")
// "1"

result := lo.Switch(2).
    Case(1, "1").
    Case(2, "2").
    Default("3")
// "2"

result := lo.Switch(42).
    Case(1, "1").
    Case(2, "2").
    Default("3")
// "3"
```

Using callbacks:

```go
result := lo.Switch(1).
    CaseF(1, func() string {
        return "1"
    }).
    CaseF(2, func() string {
        return "2"
    }).
    DefaultF(func() string {
        return "3"
    })
// "1"
```

Mixed:

```go
result := lo.Switch(1).
    CaseF(1, func() string {
        return "1"
    }).
    Default("42")
// "1"
```

[[play](https://go.dev/play/p/TGbKUMAeRUd)]

### IsNil

Checks if a value is nil or if it's a reference type with a nil underlying value.

```go
var x int
IsNil(x))
// false

var k struct{}
IsNil(k)
// false

var i *int
IsNil(i)
// true

var ifaceWithNilValue any = (*string)(nil)
IsNil(ifaceWithNilValue)
// true
ifaceWithNilValue == nil
// false
```

### ToPtr

Returns a pointer copy of the value.

```go
ptr := lo.ToPtr("hello world")
// *string{"hello world"}
```

### Nil

Returns a nil pointer of type.

```go
ptr := lo.Nil[float64]()
// nil
```

### EmptyableToPtr

Returns a pointer copy of value if it's nonzero.
Otherwise, returns nil pointer.

```go
ptr := lo.EmptyableToPtr(nil)
// nil

ptr := lo.EmptyableToPtr("")
// nil

ptr := lo.EmptyableToPtr([]int{})
// *[]int{}

ptr := lo.EmptyableToPtr("hello world")
// *string{"hello world"}
```

### FromPtr

Returns the pointer value or empty.

```go
str := "hello world"
value := lo.FromPtr(&str)
// "hello world"

value := lo.FromPtr(nil)
// ""
```

### FromPtrOr

Returns the pointer value or the fallback value.

```go
str := "hello world"
value := lo.FromPtrOr(&str, "empty")
// "hello world"

value := lo.FromPtrOr(nil, "empty")
// "empty"
```

### ToSlicePtr

Returns a slice of pointer copy of value.

```go
ptr := lo.ToSlicePtr([]string{"hello", "world"})
// []*string{"hello", "world"}
```

### FromSlicePtr

Returns a slice with the pointer values.
Returns a zero value in case of a nil pointer element.

```go
str1 := "hello"
str2 := "world"

ptr := lo.FromSlicePtr[string]([]*string{&str1, &str2, nil})
// []string{"hello", "world", ""}

ptr := lo.Compact(
    lo.FromSlicePtr[string]([]*string{&str1, &str2, nil}),
)
// []string{"hello", "world"}
```

### FromSlicePtrOr

Returns a slice with the pointer values or the fallback value.

```go
str1 := "hello"
str2 := "world"

ptr := lo.FromSlicePtrOr[string]([]*string{&str1, &str2, "fallback value"})
// []string{"hello", "world", "fallback value"}
```

### ToAnySlice

Returns a slice with all elements mapped to `any` type.

```go
elements := lo.ToAnySlice([]int{1, 5, 1})
// []any{1, 5, 1}
```

### FromAnySlice

Returns an `any` slice with all elements mapped to a type. Returns false in case of type conversion failure.

```go
elements, ok := lo.FromAnySlice([]any{"foobar", 42})
// []string{}, false

elements, ok := lo.FromAnySlice([]any{"foobar", "42"})
// []string{"foobar", "42"}, true
```

### Empty

Returns an empty value.

```go
lo.Empty[int]()
// 0
lo.Empty[string]()
// ""
lo.Empty[bool]()
// false
```

### IsEmpty

Returns true if argument is a zero value.

```go
lo.IsEmpty(0)
// true
lo.IsEmpty(42)
// false

lo.IsEmpty("")
// true
lo.IsEmpty("foobar")
// false

type test struct {
    foobar string
}

lo.IsEmpty(test{foobar: ""})
// true
lo.IsEmpty(test{foobar: "foobar"})
// false
```

### IsNotEmpty

Returns true if argument is a zero value.

```go
lo.IsNotEmpty(0)
// false
lo.IsNotEmpty(42)
// true

lo.IsNotEmpty("")
// false
lo.IsNotEmpty("foobar")
// true

type test struct {
    foobar string
}

lo.IsNotEmpty(test{foobar: ""})
// false
lo.IsNotEmpty(test{foobar: "foobar"})
// true
```

### Coalesce

Returns the first non-empty arguments. Arguments must be comparable.

```go
result, ok := lo.Coalesce(0, 1, 2, 3)
// 1 true

result, ok := lo.Coalesce("")
// "" false

var nilStr *string
str := "foobar"
result, ok := lo.Coalesce(nil, nilStr, &str)
// &"foobar" true
```

### CoalesceOrEmpty

Returns the first non-empty arguments. Arguments must be comparable.

```go
result := lo.CoalesceOrEmpty(0, 1, 2, 3)
// 1

result := lo.CoalesceOrEmpty("")
// ""

var nilStr *string
str := "foobar"
result := lo.CoalesceOrEmpty(nil, nilStr, &str)
// &"foobar"
```

### Partial

Returns new function that, when called, has its first argument set to the provided value.

```go
add := func(x, y int) int { return x + y }
f := lo.Partial(add, 5)

f(10)
// 15

f(42)
// 47
```

### Partial2 -> Partial5

Returns new function that, when called, has its first argument set to the provided value.

```go
add := func(x, y, z int) int { return x + y + z }
f := lo.Partial2(add, 42)

f(10, 5)
// 57

f(42, -4)
// 80
```

### Attempt

Invokes a function N times until it returns valid output. Returning either the caught error or nil. When first argument is less than `1`, the function runs until a successful response is returned.

```go
iter, err := lo.Attempt(42, func(i int) error {
    if i == 5 {
        return nil
    }

    return fmt.Errorf("failed")
})
// 6
// nil

iter, err := lo.Attempt(2, func(i int) error {
    if i == 5 {
        return nil
    }

    return fmt.Errorf("failed")
})
// 2
// error "failed"

iter, err := lo.Attempt(0, func(i int) error {
    if i < 42 {
        return fmt.Errorf("failed")
    }

    return nil
})
// 43
// nil
```

For more advanced retry strategies (delay, exponential backoff...), please take a look on [cenkalti/backoff](https://github.com/cenkalti/backoff).

[[play](https://go.dev/play/p/3ggJZ2ZKcMj)]

### AttemptWithDelay

Invokes a function N times until it returns valid output, with a pause between each call. Returning either the caught error or nil.

When first argument is less than `1`, the function runs until a successful response is returned.

```go
iter, duration, err := lo.AttemptWithDelay(5, 2*time.Second, func(i int, duration time.Duration) error {
    if i == 2 {
        return nil
    }

    return fmt.Errorf("failed")
})
// 3
// ~ 4 seconds
// nil
```

For more advanced retry strategies (delay, exponential backoff...), please take a look on [cenkalti/backoff](https://github.com/cenkalti/backoff).

[[play](https://go.dev/play/p/tVs6CygC7m1)]

### AttemptWhile

Invokes a function N times until it returns valid output. Returning either the caught error or nil, and along with a bool value to identifying whether it needs invoke function continuously. It will terminate the invoke immediately if second bool value is returned with falsy value.

When first argument is less than `1`, the function runs until a successful response is returned.

```go
count1, err1 := lo.AttemptWhile(5, func(i int) (error, bool) {
    err := doMockedHTTPRequest(i)
    if err != nil {
        if errors.Is(err, ErrBadRequest) { // lets assume ErrBadRequest is a critical error that needs to terminate the invoke
            return err, false // flag the second return value as false to terminate the invoke
        }

        return err, true
    }

    return nil, false
})
```

For more advanced retry strategies (delay, exponential backoff...), please take a look on [cenkalti/backoff](https://github.com/cenkalti/backoff).

[[play](https://go.dev/play/p/M2wVq24PaZM)]

### AttemptWhileWithDelay

Invokes a function N times until it returns valid output, with a pause between each call. Returning either the caught error or nil, and along with a bool value to identifying whether it needs to invoke function continuously. It will terminate the invoke immediately if second bool value is returned with falsy value.

When first argument is less than `1`, the function runs until a successful response is returned.

```go
count1, time1, err1 := lo.AttemptWhileWithDelay(5, time.Millisecond, func(i int, d time.Duration) (error, bool) {
    err := doMockedHTTPRequest(i)
    if err != nil {
        if errors.Is(err, ErrBadRequest) { // lets assume ErrBadRequest is a critical error that needs to terminate the invoke
            return err, false // flag the second return value as false to terminate the invoke
        }

        return err, true
    }

    return nil, false
})
```

For more advanced retry strategies (delay, exponential backoff...), please take a look on [cenkalti/backoff](https://github.com/cenkalti/backoff).

[[play](https://go.dev/play/p/cfcmhvLO-nv)]

### Debounce

`NewDebounce` creates a debounced instance that delays invoking functions given until after wait milliseconds have elapsed, until `cancel` is called.

```go
f := func() {
    println("Called once after 100ms when debounce stopped invoking!")
}

debounce, cancel := lo.NewDebounce(100 * time.Millisecond, f)
for j := 0; j < 10; j++ {
    debounce()
}

time.Sleep(1 * time.Second)
cancel()
```

[[play](https://go.dev/play/p/mz32VMK2nqe)]

### DebounceBy

`NewDebounceBy` creates a debounced instance for each distinct key, that delays invoking functions given until after wait milliseconds have elapsed, until `cancel` is called.

```go
f := func(key string, count int) {
    println(key + ": Called once after 100ms when debounce stopped invoking!")
}

debounce, cancel := lo.NewDebounceBy(100 * time.Millisecond, f)
for j := 0; j < 10; j++ {
    debounce("first key")
    debounce("second key")
}

time.Sleep(1 * time.Second)
cancel("first key")
cancel("second key")
```

[[play](https://go.dev/play/p/d3Vpt6pxhY8)]

### Synchronize

Wraps the underlying callback in a mutex. It receives an optional mutex.

```go
s := lo.Synchronize()

for i := 0; i < 10; i++ {
    go s.Do(func () {
        println("will be called sequentially")
    })
}
```

It is equivalent to:

```go
mu := sync.Mutex{}

func foobar() {
    mu.Lock()
    defer mu.Unlock()

    // ...
}
```

### Async

Executes a function in a goroutine and returns the result in a channel.

```go
ch := lo.Async(func() error { time.Sleep(10 * time.Second); return nil })
// chan error (nil)
```

### Async{0->6}

Executes a function in a goroutine and returns the result in a channel.
For function with multiple return values, the results will be returned as a tuple inside the channel.
For function without return, struct{} will be returned in the channel.

```go
ch := lo.Async0(func() { time.Sleep(10 * time.Second) })
// chan struct{}

ch := lo.Async1(func() int {
  time.Sleep(10 * time.Second);
  return 42
})
// chan int (42)

ch := lo.Async2(func() (int, string) {
  time.Sleep(10 * time.Second);
  return 42, "Hello"
})
// chan lo.Tuple2[int, string] ({42, "Hello"})
```

### Transaction

Implements a Saga pattern.

```go
transaction := NewTransaction().
    Then(
        func(state int) (int, error) {
            fmt.Println("step 1")
            return state + 10, nil
        },
        func(state int) int {
            fmt.Println("rollback 1")
            return state - 10
        },
    ).
    Then(
        func(state int) (int, error) {
            fmt.Println("step 2")
            return state + 15, nil
        },
        func(state int) int {
            fmt.Println("rollback 2")
            return state - 15
        },
    ).
    Then(
        func(state int) (int, error) {
            fmt.Println("step 3")

            if true {
                return state, fmt.Errorf("error")
            }

            return state + 42, nil
        },
        func(state int) int {
            fmt.Println("rollback 3")
            return state - 42
        },
    )

_, _ = transaction.Process(-5)

// Output:
// step 1
// step 2
// step 3
// rollback 2
// rollback 1
```

### WaitFor

Runs periodically until a condition is validated.

```go
alwaysTrue := func(i int) bool { return true }
alwaysFalse := func(i int) bool { return false }
laterTrue := func(i int) bool {
    return i > 5
}

iterations, duration, ok := lo.WaitFor(alwaysTrue, 10*time.Millisecond, 2 * time.Millisecond)
// 1
// 1ms
// true

iterations, duration, ok := lo.WaitFor(alwaysFalse, 10*time.Millisecond, time.Millisecond)
// 10
// 10ms
// false

iterations, duration, ok := lo.WaitFor(laterTrue, 10*time.Millisecond, time.Millisecond)
// 7
// 7ms
// true

iterations, duration, ok := lo.WaitFor(laterTrue, 10*time.Millisecond, 5*time.Millisecond)
// 2
// 10ms
// false
```


### WaitForWithContext

Runs periodically until a condition is validated or context is invalid.

The condition receives also the context, so it can invalidate the process in the condition checker

```go
ctx := context.Background()

alwaysTrue := func(_ context.Context, i int) bool { return true }
alwaysFalse := func(_ context.Context, i int) bool { return false }
laterTrue := func(_ context.Context, i int) bool {
    return i >= 5
}

iterations, duration, ok := lo.WaitForWithContext(ctx, alwaysTrue, 10*time.Millisecond, 2 * time.Millisecond)
// 1
// 1ms
// true

iterations, duration, ok := lo.WaitForWithContext(ctx, alwaysFalse, 10*time.Millisecond, time.Millisecond)
// 10
// 10ms
// false

iterations, duration, ok := lo.WaitForWithContext(ctx, laterTrue, 10*time.Millisecond, time.Millisecond)
// 5
// 5ms
// true

iterations, duration, ok := lo.WaitForWithContext(ctx, laterTrue, 10*time.Millisecond, 5*time.Millisecond)
// 2
// 10ms
// false

expiringCtx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
iterations, duration, ok := lo.WaitForWithContext(expiringCtx, alwaysFalse, 100*time.Millisecond, time.Millisecond)
// 5
// 5.1ms
// false
```

### Validate

Helper function that creates an error when a condition is not met.

```go
slice := []string{"a"}
val := lo.Validate(len(slice) == 0, "Slice should be empty but contains %v", slice)
// error("Slice should be empty but contains [a]")

slice := []string{}
val := lo.Validate(len(slice) == 0, "Slice should be empty but contains %v", slice)
// nil
```

[[play](https://go.dev/play/p/vPyh51XpCBt)]

### Must

Wraps a function call to panics if second argument is `error` or `false`, returns the value otherwise.

```go
val := lo.Must(time.Parse("2006-01-02", "2022-01-15"))
// 2022-01-15

val := lo.Must(time.Parse("2006-01-02", "bad-value"))
// panics
```

[[play](https://go.dev/play/p/TMoWrRp3DyC)]

### Must{0->6}

Must\* has the same behavior as Must, but returns multiple values.

```go
func example0() (error)
func example1() (int, error)
func example2() (int, string, error)
func example3() (int, string, time.Date, error)
func example4() (int, string, time.Date, bool, error)
func example5() (int, string, time.Date, bool, float64, error)
func example6() (int, string, time.Date, bool, float64, byte, error)

lo.Must0(example0())
val1 := lo.Must1(example1())    // alias to Must
val1, val2 := lo.Must2(example2())
val1, val2, val3 := lo.Must3(example3())
val1, val2, val3, val4 := lo.Must4(example4())
val1, val2, val3, val4, val5 := lo.Must5(example5())
val1, val2, val3, val4, val5, val6 := lo.Must6(example6())
```

You can wrap functions like `func (...) (..., ok bool)`.

```go
// math.Signbit(float64) bool
lo.Must0(math.Signbit(v))

// bytes.Cut([]byte,[]byte) ([]byte, []byte, bool)
before, after := lo.Must2(bytes.Cut(s, sep))
```

You can give context to the panic message by adding some printf-like arguments.

```go
val, ok := lo.Find(myString, func(i string) bool {
    return i == requiredChar
})
lo.Must0(ok, "'%s' must always contain '%s'", myString, requiredChar)

list := []int{0, 1, 2}
item := 5
lo.Must0(lo.Contains(list, item), "'%s' must always contain '%s'", list, item)
...
```

[[play](https://go.dev/play/p/TMoWrRp3DyC)]

### Try

Calls the function and returns false in case of error and panic.

```go
ok := lo.Try(func() error {
    panic("error")
    return nil
})
// false

ok := lo.Try(func() error {
    return nil
})
// true

ok := lo.Try(func() error {
    return fmt.Errorf("error")
})
// false
```

[[play](https://go.dev/play/p/mTyyWUvn9u4)]

### Try{0->6}

The same behavior as `Try`, but the callback returns 2 variables.

```go
ok := lo.Try2(func() (string, error) {
    panic("error")
    return "", nil
})
// false
```

[[play](https://go.dev/play/p/mTyyWUvn9u4)]

### TryOr

Calls the function and return a default value in case of error and on panic.

```go
str, ok := lo.TryOr(func() (string, error) {
    panic("error")
    return "hello", nil
}, "world")
// world
// false

str, ok := lo.TryOr(func() error {
    return "hello", nil
}, "world")
// hello
// true

str, ok := lo.TryOr(func() error {
    return "hello", fmt.Errorf("error")
}, "world")
// world
// false
```

[[play](https://go.dev/play/p/B4F7Wg2Zh9X)]

### TryOr{0->6}

The same behavior as `TryOr`, but the callback returns `X` variables.

```go
str, nbr, ok := lo.TryOr2(func() (string, int, error) {
    panic("error")
    return "hello", 42, nil
}, "world", 21)
// world
// 21
// false
```

[[play](https://go.dev/play/p/B4F7Wg2Zh9X)]

### TryWithErrorValue

The same behavior as `Try`, but also returns the value passed to panic.

```go
err, ok := lo.TryWithErrorValue(func() error {
    panic("error")
    return nil
})
// "error", false
```

[[play](https://go.dev/play/p/Kc7afQIT2Fs)]

### TryCatch

The same behavior as `Try`, but calls the catch function in case of error.

```go
caught := false

ok := lo.TryCatch(func() error {
    panic("error")
    return nil
}, func() {
    caught = true
})
// false
// caught == true
```

[[play](https://go.dev/play/p/PnOON-EqBiU)]

### TryCatchWithErrorValue

The same behavior as `TryWithErrorValue`, but calls the catch function in case of error.

```go
caught := false

ok := lo.TryCatchWithErrorValue(func() error {
    panic("error")
    return nil
}, func(val any) {
    caught = val == "error"
})
// false
// caught == true
```

[[play](https://go.dev/play/p/8Pc9gwX_GZO)]

### ErrorsAs

A shortcut for:

```go
err := doSomething()

var rateLimitErr *RateLimitError
if ok := errors.As(err, &rateLimitErr); ok {
    // retry later
}
```

1 line `lo` helper:

```go
err := doSomething()

if rateLimitErr, ok := lo.ErrorsAs[*RateLimitError](err); ok {
    // retry later
}
```

[[play](https://go.dev/play/p/8wk5rH8UfrE)]

## 🛩 Benchmark

We executed a simple benchmark with a dead-simple `lo.Map` loop:

See the full implementation [here](./benchmark_test.go).

```go
_ = lo.Map[int64](arr, func(x int64, i int) string {
    return strconv.FormatInt(x, 10)
})
```

**Result:**

Here is a comparison between `lo.Map`, `lop.Map`, `go-funk` library and a simple Go `for` loop.

```shell
$ go test -benchmem -bench ./...
goos: linux
goarch: amd64
pkg: github.com/samber/lo
cpu: Intel(R) Core(TM) i5-7267U CPU @ 3.10GHz
cpu: Intel(R) Core(TM) i7 CPU         920  @ 2.67GHz
BenchmarkMap/lo.Map-8         	       8	 132728237 ns/op	39998945 B/op	 1000002 allocs/op
BenchmarkMap/lop.Map-8        	       2	 503947830 ns/op	119999956 B/op	 3000007 allocs/op
BenchmarkMap/reflect-8        	       2	 826400560 ns/op	170326512 B/op	 4000042 allocs/op
BenchmarkMap/for-8            	       9	 126252954 ns/op	39998674 B/op	 1000001 allocs/op
PASS
ok  	github.com/samber/lo	6.657s
```

- `lo.Map` is way faster (x7) than `go-funk`, a reflection-based Map implementation.
- `lo.Map` have the same allocation profile than `for`.
- `lo.Map` is 4% slower than `for`.
- `lop.Map` is slower than `lo.Map` because it implies more memory allocation and locks. `lop.Map` will be useful for long-running callbacks, such as i/o bound processing.
- `for` beats other implementations for memory and CPU.

## 🤝 Contributing

- Ping me on Twitter [@samuelberthe](https://twitter.com/samuelberthe) (DMs, mentions, whatever :))
- Fork the [project](https://github.com/samber/lo)
- Fix [open issues](https://github.com/samber/lo/issues) or request new features

Don't hesitate ;)

Helper naming: helpers must be self-explanatory and respect standards (other languages, libraries...). Feel free to suggest many names in your contributions.

### With Docker

```bash
docker-compose run --rm dev
```

### Without Docker

```bash
# Install some dev dependencies
make tools

# Run tests
make test
# or
make watch-test
```

## 👤 Contributors

![Contributors](https://contrib.rocks/image?repo=samber/lo)

## 💫 Show your support

Give a ⭐️ if this project helped you!

[![GitHub Sponsors](https://img.shields.io/github/sponsors/samber?style=for-the-badge)](https://github.com/sponsors/samber)

## 📝 License

Copyright © 2022 [Samuel Berthe](https://github.com/samber).

This project is under [MIT](./LICENSE) license.
