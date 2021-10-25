# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.12.0] - 2021-07-29
### Added
- Support for ProvideInfo and FillProvideInfo that allow the caller of
  `Provide` to get info about what dig understood from the constructor.

## [1.11.0] - 2021-06-09
### Added
- Support unexported fields on `dig.In` structs with the
  `ignore-unexported:"true` struct tag.

## [1.10.0] - 2020-06-16
### Added
- Introduce `DryRun` Option which, when set to true, disables invocation
  of functions supplied to `Provide` and `Invoke`. This option will be
  used to build no-op containers, for example for `fx.ValidateApp` method.

## [1.9.0] - 2020-03-31
### Added
- GraphViz visualization of the graph now includes names of packages next to
  constructors.
- Added a `flatten` modifier to group tags for slices to allow providing
  individual elements instead of the slice for a group value. See package
  doucmentation for more information.

### Changed
- Drop library dependency on `golang.org/x/lint`.
- Support printing multi-line error messages with `%+v`.

## [1.8.0] - 2019-11-14
### Changed
- Migrated to Go modules.

## [1.7.0] - 2019-01-04
### Added
- Added `Group` option for `Provide` to add value groups to the container without
rewriting constructors. See package doucmentation for more information.

## [1.6.0] - 2018-11-06
### Changed
- When an error graph is visualized, the graph is pruned so that the graph only
  contains failure nodes.
- Container visualization is now oriented from right to left.

## [1.5.1] - 2018-11-01
### Fixed
- Fixed a test that was causing Dig to be unusable with Go Modules.

## [1.5.0] - 2018-09-19
### Added
- Added a `DeferAcyclicVerification` container option that defers graph cycle
  detection until the next Invoke.

### Changed
- Improved cycle-detection performance by 50x in certain degenerative cases.

## [1.4.0] - 2018-08-16
### Added
- Added `Visualize` function to visualize the state of the container in the
  GraphViz DOT format. This allows visualization of error types and the
  dependency relationships of types in the container.
- Added `CanVisualizeError` function to determine if an error can be visualized
  in the graph.
- Added `Name` option for `Provide` to add named values to the container
  without rewriting constructors. See package documentation for more
  information.

### Changed
- `name:"..."` tags on nested Result Objects will now cause errors instead of
  being ignored.

## [1.3.0] - 2017-12-04
### Changed
- Improved messages for errors thrown by Dig under a many scenarios to be more
  informative.

## [1.2.0] - 2017-11-07
### Added
- `dig.In` and `dig.Out` now support value groups, making it possible to
  produce many values of the same type from different constructors. See package
  documentation for more information.

## [1.1.0] - 2017-09-15
### Added
- Added the `dig.RootCause` function which allows retrieving the original
  constructor error that caused an `Invoke` failure.

### Changed
- Errors from `Invoke` now attempt to hint to the user a presence of a similar
  type, for example a pointer to the requested type and vice versa.

## [1.0.0] - 2017-07-31

First stable release: no breaking changes will be made in the 1.x series.

### Changed
- `Provide` and `Invoke` will now fail if `dig.In` or `dig.Out` structs
  contain unexported fields. Previously these fields were ignored which often
  led to confusion.

## [1.0.0-rc2] - 2017-07-21
### Added
- Exported `dig.IsIn` and `dig.IsOut` so that consuming libraries can check if
  a params or return struct embeds the `dig.In` and `dig.Out` types, respectively.

### Changed
- Added variadic options to all public APIS so that new functionality can be
  introduced post v1.0.0 without introducing breaking changes.
- Functions with variadic arguments can now be passed to `dig.Provide` and
  `dig.Invoke`. Previously this caused an error, whereas now the args will be ignored.

## [1.0.0-rc1] - 2017-06-21

First release candidate.

## [0.5.0] - 2017-06-19
### Added
- `dig.In` and `dig.Out` now support named instances, i.e.:

    ```go
    type param struct {
      dig.In

      DB1 DB.Connection `name:"primary"`
      DB2 DB.Connection `name:"secondary"`
    }
    ```

### Fixed
- Structs compatible with `dig.In` and `dig.Out` may now be generated using
  `reflect.StructOf`.

## [0.4.0] - 2017-06-12
### Added
- Add `dig.In` embeddable type for advanced use-cases of specifying dependencies.
- Add `dig.Out` embeddable type for advanced use-cases of constructors
  inserting types in the container.
- Add support for optional parameters through `optional:"true"` tag on `dig.In` objects.
- Add support for value types and many built-ins (maps, slices, channels).

### Changed
- **[Breaking]** Restrict the API surface to only `Provide` and `Invoke`.
- **[Breaking]** Update `Provide` method to accept variadic arguments.

### Removed
- **[Breaking]** Remove `Must*` funcs to greatly reduce API surface area.
- Providing constructors with common returned types results in an error.

## [0.3] - 2017-05-02
### Added
- Add functionality to `Provide` to support constructor with `n` return
  objects to be resolved into the `dig.Graph`
- Add `Invoke` function to invoke provided function and insert return
  objects into the `dig.Graph`

### Changed
- Rename `RegisterAll` and `MustRegisterAll` to `ProvideAll` and
  `MustProvideAll`.

## [0.2] - 2017-03-27
### Changed
- Rename `Register` to `Provide` for clarity and to recude clash with other
  Register functions.
- Rename `dig.Graph` to `dig.Container`.

### Removed
- Remove the package-level functions and the `DefaultGraph`.

## 0.1 - 2017-03-23

Initial release.

[1.11.0]: https://github.com/uber-go/dig/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/uber-go/dig/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/uber-go/dig/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/uber-go/dig/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/uber-go/dig/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/uber-go/dig/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/uber-go/dig/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/uber-go/dig/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/uber-go/dig/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/uber-go/dig/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/uber-go/dig/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/uber-go/dig/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/uber-go/dig/compare/v1.0.0-rc2...v1.0.0
[1.0.0-rc2]: https://github.com/uber-go/dig/compare/v1.0.0-rc1...v1.0.0-rc2
[1.0.0-rc1]: https://github.com/uber-go/dig/compare/v0.5.0...v1.0.0-rc1
[0.5.0]: https://github.com/uber-go/dig/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/uber-go/dig/compare/v0.3...v0.4.0
[0.3]: https://github.com/uber-go/dig/compare/v0.2...v0.3
[0.2]: https://github.com/uber-go/dig/compare/v0.1...v0.2
