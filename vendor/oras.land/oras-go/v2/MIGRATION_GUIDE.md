# Migration Guide

In version `v2`, ORAS Go library has been completely refreshed with:

- More unified interfaces
- Notably fewer dependencies
- Higher test coverage
- Better documentation

**Additionally, ORAS Go `v2` is now a registry client.**

## Major Changes in `v2`

- Content store
  - [`content.File`](https://pkg.go.dev/oras.land/oras-go/pkg/content#File) is now [`file.Store`](https://pkg.go.dev/oras.land/oras-go/v2/content/file#Store)
  - [`content.OCI`](https://pkg.go.dev/oras.land/oras-go/pkg/content#OCI) is now [`oci.Store`](https://pkg.go.dev/oras.land/oras-go/v2/content/oci#Store)
  - [`content.Memory`](https://pkg.go.dev/oras.land/oras-go/pkg/content#Memory) is now [`memory.Store`](https://pkg.go.dev/oras.land/oras-go/v2/content/memory#Store)
- Registry interaction
  - Introduces an [SDK](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote) to interact with OCI-compliant and Docker-compliant registries
- Authentication
  - Implements authentication through [`auth.Client`](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote/auth#Client) and supports credential management via [`credentials`](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote/credentials)
- Copy operations
  - Enhances artifact [copying](https://pkg.go.dev/oras.land/oras-go/v2#Copy) capabilities between various [`Target`](https://pkg.go.dev/oras.land/oras-go/v2#Target) with flexible options
  - Enables [extended-copying](https://pkg.go.dev/oras.land/oras-go/v2#ExtendedCopy) of artifacts along with their predecessors (e.g., referrers)

## Migrating from `v1` to `v2`

1. Get the `v2` package

    ```sh
    go get oras.land/oras-go/v2
    ```

2. Import and use the `v2` package

    ```go
    import "oras.land/oras-go/v2"
    ```

3. Run

   ```sh
   go mod tidy
    ```

Since breaking changes are introduced in `v2`, code refactoring is required for migrating from `v1` to `v2`.  
The migration can be done in an iterative fashion, as `v1` and `v2` can be imported and used at the same time.

For comprehensive documentation and examples, please refer to [pkg.go.dev](https://pkg.go.dev/oras.land/oras-go/v2).

## FAQs

### Is there a 1:1 mapping of APIs between `v1` and `v2`?

No, `v2` does not have a direct 1:1 mapping of APIs with `v1`, as the structure of the APIs has been significantly redesigned. Instead of looking for a direct replacement, see this as a chance to upgrade your application with `v2`'s new features.

You can explore the [end-to-end examples](https://pkg.go.dev/oras.land/oras-go/v2#pkg-overview) that demonstrate the usage of v2 in practical scenarios.

## Community Support

If you encounter challenges during migration, seek assistance from the community by [submitting GitHub issues](https://github.com/oras-project/oras-go/issues/new) or asking in the [#oras](https://cloud-native.slack.com/archives/CJ1KHJM5Z) Slack channel.
