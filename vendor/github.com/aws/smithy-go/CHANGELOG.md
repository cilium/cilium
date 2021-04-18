# Release v1.3.1 (2021-04-08)

### Smithy Go module
* `transport/http`: Loosen endpoint hostname validation to allow specifying port numbers. ([#279](https://github.com/aws/smithy-go/pull/279))
* `io`: Fix RingBuffer panics due to out of bounds index. ([#282](https://github.com/aws/smithy-go/pull/282))

# Release v1.3.0 (2021-04-01)

### Smithy Go module
* `transport/http`: Add utility to safely join string to url path, and url raw query.

### Codegen
* Update HttpBindingProtocolGenerator to use http/transport JoinPath and JoinQuery utility.

# Release v1.2.0 (2021-03-12)

### Smithy Go module
* Fix support for parsing shortened year format in HTTP Date header.
* Fix GitHub APIDiff action workflow to get gorelease tool correctly.
* Fix codegen artifact unit test for Go 1.16

### Codegen
* Fix generating paginator nil parameter handling before usage.
* Fix Serialize unboxed members decorated as required.
* Add ability to define resolvers at both client construction and operation invocation.
* Support for extending paginators with custom runtime trait
