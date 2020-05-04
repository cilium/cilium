# Slim Kubernetes structures

This package is intended to be a slim copy of the structures used in k8s watchers.

The most common structures are under `vendor/k8s.io/api/core/v1/types.go`, or
`vendor/k8s.io/apimachinery/pkg/apis/meta/v1/types.go`. 

All fields of the copied structures are exactly the same as the ones available
in the official k8s source code. To keep a slimmer version of these structures
make sure the unused fields by Cilium are removed from the slimmer versions.

If new fields need to be added or removed to these structures, some files need
to be regenerated with `make generate-k8s-api` in the root directory of this
repository.

The directory `./k8s/client` is entirely auto-generated. This directory has the
source code of an optimized Kubernetes client.

With this optimized Kubernetes client we can wrap some official and
non-optimized Kubernetes interfaces with the ones built for the slimmer
versions. So make sure you are correctly wrapping the interfaces with our
implementations. If this client is used a structure that is not registered under
"register.go" of that package or if the client is being used for a type that is
not optimized yet, you will hit the error:
`Failed to list ... no kind "..." is registered for version "v1"`. To fix this
make sure the package is registered and the client is supposed to be used
for that structure.
