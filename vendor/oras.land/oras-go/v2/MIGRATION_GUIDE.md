# Migration Guide

In version `v2`, ORAS Go library has been completely refreshed with:

- More unified interfaces
- Notably fewer dependencies
- Higher test coverage
- Better documentation

**Besides, ORAS Go `v2` is now a registry client.**

## Major Changes in `v2`

- Moves `content.FileStore` to [file.Store](https://pkg.go.dev/oras.land/oras-go/v2/content/file#Store)
- Moves `content.OCIStore` to [oci.Store](https://pkg.go.dev/oras.land/oras-go/v2/content/oci#Store)
- Moves `content.MemoryStore` to [memory.Store](https://pkg.go.dev/oras.land/oras-go/v2/content/memory#Store)
- Provides [SDK](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote) to interact with OCI-compliant and Docker-compliant registries
- Supports [Copy](https://pkg.go.dev/oras.land/oras-go/v2#Copy) with more flexible options
- Supports [Extended Copy](https://pkg.go.dev/oras.land/oras-go/v2#ExtendedCopy) with options *(experimental)*
- No longer supports `docker.Login` and `docker.Logout` (removes the dependency on `docker`); instead, provides authentication through [auth.Client](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote/auth#Client)

Documentation and examples are available at [pkg.go.dev](https://pkg.go.dev/oras.land/oras-go/v2).

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
