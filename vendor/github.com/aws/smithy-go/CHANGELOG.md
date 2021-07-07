# Release v1.5.0 (2021-06-25)

### Smithy Go module
* `time`: Update time parsing to not be as strict for HTTPDate and DateTime ([#307](https://github.com/aws/smithy-go/pull/307)) 
  * Fixes [#302](https://github.com/aws/smithy-go/issues/302) by changing time to UTC before formatting so no local offset time is lost.

### Codegen
* Adds support for integrating client members via plugins ([#301](https://github.com/aws/smithy-go/pull/301))
* Fix serialization of enum types marked with payload trait ([#296](https://github.com/aws/smithy-go/pull/296))
* Update generation of API client modules to include a manifest of files generated ([#283](https://github.com/aws/smithy-go/pull/283))
* Update Group Java group ID for smithy-go generator ([#298](https://github.com/aws/smithy-go/pull/298))
* Support the delegation of determining the errors that can occur for an operation ([#304](https://github.com/aws/smithy-go/pull/304))
* Support for marking and documenting deprecated client config fields. ([#303](https://github.com/aws/smithy-go/pull/303))

# Release v1.4.0 (2021-05-06)

### Smithy Go module
* `encoding/xml`: Fix escaping of Next Line and Line Start in XML Encoder ([#267](https://github.com/aws/smithy-go/pull/267))

### Codegen
* Add support for Smithy 1.7 ([#289](https://github.com/aws/smithy-go/pull/289))
* Add support for httpQueryParams location
* Add support for model renaming conflict resolution with service closure

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
