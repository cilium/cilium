# Changelog

@samber: I sometimes forget to update this file. Ping me on [Twitter](https://twitter.com/samuelberthe) or open an issue in case of error. We need to keep a clear changelog for easier lib upgrade.

## 1.39.0 (2023-12-01)

Improvement:
- Adding IsNil

## 1.38.1 (2023-03-20)

Improvement:
- Async and AsyncX: now returns `<-chan T` instead of `chan T`

## 1.38.0 (2023-03-20)

Adding:
- lo.ValueOr
- lo.DebounceBy
- lo.EmptyableToPtr

Improvement:
- Substring: add support for non-English chars

Fix:
- Async: Fix goroutine leak

## 1.37.0 (2022-12-15)

Adding:
- lo.PartialX
- lo.Transaction

Improvement:
- lo.Associate / lo.SliceToMap: faster memory allocation

Chore:
- Remove *_test.go files from releases, in order to cleanup dev dependencies

## 1.36.0 (2022-11-28)

Adding:
- lo.AttemptWhile
- lo.AttemptWhileWithDelay

## 1.35.0 (2022-11-15)

Adding:
- lo.RandomString
- lo.BufferWithTimeout (alias to lo.BatchWithTimeout)
- lo.Buffer (alias to lo.Batch)

Change:
- lo.Slice: avoid panic caused by out-of-bounds

Deprecation:
- lo.BatchWithTimeout
- lo.Batch

## 1.34.0 (2022-11-12)

Improving:
- lo.Union: faster and can receive more than 2 lists

Adding:
- lo.FanIn (alias to lo.ChannelMerge)
- lo.FanOut

Deprecation:
- lo.ChannelMerge

## 1.33.0 (2022-10-14)

Adding:
- lo.ChannelMerge

Improving:
- helpers with callbacks/predicates/iteratee now have named arguments, for easier autocompletion

## 1.32.0 (2022-10-10)

Adding:

- lo.ChannelToSlice
- lo.CountValues
- lo.CountValuesBy
- lo.MapEntries
- lo.Sum
- lo.Interleave
- TupleX.Unpack()

## 1.31.0 (2022-10-06)

Adding:

- lo.SliceToChannel
- lo.Generator
- lo.Batch
- lo.BatchWithTimeout

## 1.30.1 (2022-10-06)

Fix:

- lo.Try1: remove generic type
- lo.Validate: format error properly

## 1.30.0 (2022-10-04)

Adding:

- lo.TernaryF
- lo.Validate

## 1.29.0 (2022-10-02)

Adding:

- lo.ErrorAs
- lo.TryOr
- lo.TryOrX

## 1.28.0 (2022-09-05)

Adding:

- lo.ChannelDispatcher with 6 dispatching strategies:
  - lo.DispatchingStrategyRoundRobin
  - lo.DispatchingStrategyRandom
  - lo.DispatchingStrategyWeightedRandom
  - lo.DispatchingStrategyFirst
  - lo.DispatchingStrategyLeast
  - lo.DispatchingStrategyMost

## 1.27.1 (2022-08-15)

Bugfix:

- Removed comparable constraint for lo.FindKeyBy

## 1.27.0 (2022-07-29)

Breaking:

- Change of MapToSlice prototype: `MapToSlice[K comparable, V any, R any](in map[K]V, iteratee func(V, K) R) []R` -> `MapToSlice[K comparable, V any, R any](in map[K]V, iteratee func(K, V) R) []R`

Added:

- lo.ChunkString
- lo.SliceToMap (alias to lo.Associate)

## 1.26.0 (2022-07-24)

Adding:

- lo.Associate
- lo.ReduceRight
- lo.FromPtrOr
- lo.MapToSlice
- lo.IsSorted
- lo.IsSortedByKey

## 1.25.0 (2022-07-04)

Adding:

- lo.FindUniques
- lo.FindUniquesBy
- lo.FindDuplicates
- lo.FindDuplicatesBy
- lo.IsNotEmpty

## 1.24.0 (2022-07-04)

Adding:

- lo.Without
- lo.WithoutEmpty

## 1.23.0 (2022-07-04)

Adding:

- lo.FindKey
- lo.FindKeyBy

## 1.22.0 (2022-07-04)

Adding:

- lo.Slice
- lo.FromPtr
- lo.IsEmpty
- lo.Compact
- lo.ToPairs: alias to lo.Entries
- lo.FromPairs: alias to lo.FromEntries
- lo.Partial

Change:

- lo.Must + lo.MustX: add context to panic message

Fix:

- lo.Nth: out of bound exception (#137)

## 1.21.0 (2022-05-10)

Adding:

- lo.ToAnySlice
- lo.FromAnySlice

## 1.20.0 (2022-05-02)

Adding:

- lo.Synchronize
- lo.SumBy

Change:
- Removed generic type definition for lo.Try0: `lo.Try0[T]()` -> `lo.Try0()`

## 1.19.0 (2022-04-30)

Adding:

- lo.RepeatBy
- lo.Subset
- lo.Replace
- lo.ReplaceAll
- lo.Substring
- lo.RuneLength

## 1.18.0 (2022-04-28)

Adding:

- lo.SomeBy
- lo.EveryBy
- lo.None
- lo.NoneBy

## 1.17.0 (2022-04-27)

Adding:

- lo.Unpack2 -> lo.Unpack3
- lo.Async0 -> lo.Async6

## 1.16.0 (2022-04-26)

Adding:

- lo.AttemptWithDelay

## 1.15.0 (2022-04-22)

Improvement:

- lo.Must: error or boolean value

## 1.14.0 (2022-04-21)

Adding:

- lo.Coalesce

## 1.13.0 (2022-04-14)

Adding:

- PickBy
- PickByKeys
- PickByValues
- OmitBy
- OmitByKeys
- OmitByValues
- Clamp
- MapKeys
- Invert
- IfF + ElseIfF + ElseF
- T0() + T1() + T2() + T3() + ...

## 1.12.0 (2022-04-12)

Adding:

- Must
- Must{0-6}
- FindOrElse
- Async
- MinBy
- MaxBy
- Count
- CountBy
- FindIndexOf
- FindLastIndexOf
- FilterMap

## 1.11.0 (2022-03-11)

Adding:

- Try
- Try{0-6}
- TryWitchValue
- TryCatch
- TryCatchWitchValue
- Debounce
- Reject

## 1.10.0 (2022-03-11)

Adding:

- Range
- RangeFrom
- RangeWithSteps

## 1.9.0 (2022-03-10)

Added

- Drop
- DropRight
- DropWhile
- DropRightWhile

## 1.8.0 (2022-03-10)

Adding Union.

## 1.7.0 (2022-03-09)

Adding ContainBy

Adding MapValues

Adding FlatMap

## 1.6.0 (2022-03-07)

Fixed PartitionBy.

Adding Sample

Adding Samples

## 1.5.0 (2022-03-07)

Adding Times

Adding Attempt

Adding Repeat

## 1.4.0 (2022-03-07)

- adding tuple types (2->9)
- adding Zip + Unzip
- adding lo.PartitionBy + lop.PartitionBy
- adding lop.GroupBy
- fixing Nth

## 1.3.0 (2022-03-03)

Last and Nth return errors

## 1.2.0 (2022-03-03)

Adding `lop.Map` and `lop.ForEach`.

## 1.1.0 (2022-03-03)

Adding `i int` param to `lo.Map()`, `lo.Filter()`, `lo.ForEach()` and `lo.Reduce()` predicates.

## 1.0.0 (2022-03-02)

*Initial release*

Supported helpers for slices:

- Filter
- Map
- Reduce
- ForEach
- Uniq
- UniqBy
- GroupBy
- Chunk
- Flatten
- Shuffle
- Reverse
- Fill
- ToMap

Supported helpers for maps:

- Keys
- Values
- Entries
- FromEntries
- Assign (maps merge)

Supported intersection helpers:

- Contains
- Every
- Some
- Intersect
- Difference

Supported search helpers:

- IndexOf
- LastIndexOf
- Find
- Min
- Max
- Last
- Nth

Other functional programming helpers:

- Ternary (1 line if/else statement)
- If / ElseIf / Else
- Switch / Case / Default
- ToPtr
- ToSlicePtr

Constraints:

- Clonable
