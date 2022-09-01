# :unicorn: Fx [![GoDoc][doc-img]][doc] [![Github release][release-img]][release] [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov] [![Go Report Card](https://goreportcard.com/badge/go.uber.org/fx)](https://goreportcard.com/report/go.uber.org/fx)

An application framework for Go that:

- Makes dependency injection easy.
- Eliminates the need for global state and `func init()`.

## Installation

We recommend locking to [SemVer](http://semver.org/) range `^1` using [go mod](https://github.com/golang/go/wiki/Modules):

```shell
go get go.uber.org/fx@v1
```

## Stability

This library is `v1` and follows [SemVer](http://semver.org/) strictly.

No breaking changes will be made to exported APIs before `v2.0.0`.

This project follows the [Go Release Policy][release-policy]. Each major
version of Go is supported until there are two newer major releases.

[doc-img]: https://pkg.go.dev/badge/go.uber.org/fx
[doc]: https://pkg.go.dev/go.uber.org/fx
[release-img]: https://img.shields.io/github/release/uber-go/fx.svg
[release]: https://github.com/uber-go/fx/releases
[ci-img]: https://github.com/uber-go/fx/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/uber-go/fx/actions/workflows/go.yml
[cov-img]: https://codecov.io/gh/uber-go/fx/branch/master/graph/badge.svg
[cov]: https://codecov.io/gh/uber-go/fx/branch/master
[report-card-img]: https://goreportcard.com/badge/github.com/uber-go/fx
[report-card]: https://goreportcard.com/report/github.com/uber-go/fx
[release-policy]: https://golang.org/doc/devel/release.html#policy
