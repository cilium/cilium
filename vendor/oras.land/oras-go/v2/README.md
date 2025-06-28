# ORAS Go library

[![Build Status](https://github.com/oras-project/oras-go/actions/workflows/build.yml/badge.svg?event=push&branch=main)](https://github.com/oras-project/oras-go/actions/workflows/build.yml?query=workflow%3Abuild+event%3Apush+branch%3Amain)
[![codecov](https://codecov.io/gh/oras-project/oras-go/branch/main/graph/badge.svg)](https://codecov.io/gh/oras-project/oras-go)
[![Go Report Card](https://goreportcard.com/badge/oras.land/oras-go/v2)](https://goreportcard.com/report/oras.land/oras-go/v2)
[![Go Reference](https://pkg.go.dev/badge/oras.land/oras-go/v2.svg)](https://pkg.go.dev/oras.land/oras-go/v2)

<p align="left">
<a href="https://oras.land/"><img src="https://oras.land/img/oras.svg" alt="ORAS logo" width="100px"></a>
</p>

`oras-go` is a Go library for managing OCI artifacts, compliant with the [OCI Image Format Specification](https://github.com/opencontainers/image-spec) and the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec). It provides unified APIs for pushing, pulling, and managing artifacts across OCI-compliant registries, local file systems, and in-memory stores.

> [!Note]
> The `main` branch follows [Go's Security Policy](https://github.com/golang/go/security/policy) and supports the two latest versions of Go (currently `1.23` and `1.24`).

## Getting Started

### Concepts

Gain insights into the fundamental concepts:

- [Modeling Artifacts](docs/Modeling-Artifacts.md)
- [Targets and Content Stores](docs/Targets.md)

### Quickstart

Follow the step-by-step tutorial to use `oras-go` v2:

- [Quickstart: Managing OCI Artifacts with `oras-go` v2](docs/tutorial/quickstart.md)

### Examples

Check out sample code for common use cases:

- [Artifact copying](https://pkg.go.dev/oras.land/oras-go/v2#pkg-examples)
- [Registry operations](https://pkg.go.dev/oras.land/oras-go/v2/registry#pkg-examples)
- [Repository operations](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote#pkg-examples)
- [Authentication](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote/auth#pkg-examples)
- [Credentials management](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote/credentials#pkg-examples)

Find more API examples at [pkg.go.dev](https://pkg.go.dev/oras.land/oras-go/v2).


## Versioning

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR`.`MINOR`.`PATCH`), with `MAJOR` for breaking changes, `MINOR` for backward-compatible features, and `PATCH` for backward-compatible fixes.

## Previous Major Versions

### v1 (maintenance)

[![Build Status](https://github.com/oras-project/oras-go/actions/workflows/build.yml/badge.svg?event=push&branch=v1)](https://github.com/oras-project/oras-go/actions/workflows/build.yml?query=workflow%3Abuild+event%3Apush+branch%3Av1)
[![Go Report Card](https://goreportcard.com/badge/oras.land/oras-go)](https://goreportcard.com/report/oras.land/oras-go)
[![Go Reference](https://pkg.go.dev/badge/oras.land/oras-go.svg)](https://pkg.go.dev/oras.land/oras-go)

The [`v1`](https://github.com/oras-project/oras-go/tree/v1) branch is maintained for dependency updates and security fixes only. All feature development happens in the [`main`](https://github.com/oras-project/oras-go/tree/main) branch.

To migrate from `v1` to `v2`, see [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md).

## Community

- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security Policy: [SECURITY.md](SECURITY.md)
- Reviewing Guide: [Reviewing Guide](https://github.com/oras-project/community/blob/main/REVIEWING.md)
- Slack: [`#oras`](https://cloud-native.slack.com/archives/CJ1KHJM5Z) channel on CNCF Slack
