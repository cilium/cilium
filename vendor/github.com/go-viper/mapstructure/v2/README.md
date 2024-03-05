# mapstructure

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/go-viper/mapstructure/ci.yaml?branch=main&style=flat-square)](https://github.com/go-viper/mapstructure/actions?query=workflow%3ACI)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/go-viper/mapstructure/v2)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.18-61CFDD.svg?style=flat-square)

mapstructure is a Go library for decoding generic map values to structures
and vice versa, while providing helpful error handling.

This library is most useful when decoding values from some data stream (JSON,
Gob, etc.) where you don't _quite_ know the structure of the underlying data
until you read a part of it. You can therefore read a `map[string]interface{}`
and use this library to decode it into the proper underlying native Go
structure.

## Installation

```shell
go get github.com/go-viper/mapstructure/v2
```

## Usage & Example

For usage and examples see the [documentation](https://pkg.go.dev/mod/github.com/go-viper/mapstructure/v2).

The `Decode` function has examples associated with it there.

## But Why?!

Go offers fantastic standard libraries for decoding formats such as JSON.
The standard method is to have a struct pre-created, and populate that struct
from the bytes of the encoded format. This is great, but the problem is if
you have configuration or an encoding that changes slightly depending on
specific fields. For example, consider this JSON:

```json
{
  "type": "person",
  "name": "Mitchell"
}
```

Perhaps we can't populate a specific structure without first reading
the "type" field from the JSON. We could always do two passes over the
decoding of the JSON (reading the "type" first, and the rest later).
However, it is much simpler to just decode this into a `map[string]interface{}`
structure, read the "type" key, then use something like this library
to decode it into the proper structure.

## Credits

Mapstructure was originally created by [@mitchellh](https://github.com/mitchellh).
This is a maintained fork of the original library.

Read more about the reasons for the fork [here](https://github.com/mitchellh/mapstructure/issues/349).

## License

The project is licensed under the [MIT License](LICENSE).
