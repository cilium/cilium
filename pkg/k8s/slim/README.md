# Slim Kubernetes structures

This package is intended to be a slim copy of the structures used in k8s watchers.

The most common structures are under `vendor/k8s.io/api/core/v1/types.go`, or
`vendor/k8s.io/apimachinery/pkg/apis/meta/v1/types.go`. 

```bash
tag=v1.25.0
url="https://raw.githubusercontent.com/kubernetes/kubernetes/${tag}"

curl "${url}/staging/src/k8s.io/api/core/v1/doc.go" > pkg/k8s/slim/k8s/api/core/v1/doc.go
curl "${url}/staging/src/k8s.io/api/core/v1/register.go" > pkg/k8s/slim/k8s/api/core/v1/register.go
curl "${url}/staging/src/k8s.io/api/core/v1/taint.go" > pkg/k8s/slim/k8s/api/core/v1/taint.go
curl "${url}/staging/src/k8s.io/api/core/v1/types.go" > pkg/k8s/slim/k8s/api/core/v1/types.go

curl "${url}/staging/src/k8s.io/api/discovery/v1beta1/doc.go" > pkg/k8s/slim/k8s/api/discovery/v1beta1/doc.go
curl "${url}/staging/src/k8s.io/api/discovery/v1beta1/register.go" > pkg/k8s/slim/k8s/api/discovery/v1beta1/register.go
curl "${url}/staging/src/k8s.io/api/discovery/v1beta1/types.go" > pkg/k8s/slim/k8s/api/discovery/v1beta1/types.go
curl "${url}/staging/src/k8s.io/api/discovery/v1beta1/well_known_labels.go" > pkg/k8s/slim/k8s/api/discovery/v1beta1/well_known_labels.go

curl "${url}/staging/src/k8s.io/api/discovery/v1/doc.go" > pkg/k8s/slim/k8s/api/discovery/v1/doc.go
curl "${url}/staging/src/k8s.io/api/discovery/v1/register.go" > pkg/k8s/slim/k8s/api/discovery/v1/register.go
curl "${url}/staging/src/k8s.io/api/discovery/v1/types.go" > pkg/k8s/slim/k8s/api/discovery/v1/types.go
curl "${url}/staging/src/k8s.io/api/discovery/v1/well_known_labels.go" > pkg/k8s/slim/k8s/api/discovery/v1/well_known_labels.go

curl "${url}/staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/doc.go" > pkg/k8s/slim/k8s/apis/apiextensions/v1/doc.go
curl "${url}/staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/register.go" > pkg/k8s/slim/k8s/apis/apiextensions/v1/register.go
curl "${url}/staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1/types.go" > pkg/k8s/slim/k8s/apis/apiextensions/v1/types.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/labels/doc.go" > pkg/k8s/slim/k8s/apis/labels/doc.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/labels/labels.go" > pkg/k8s/slim/k8s/apis/labels/labels.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/labels/selector.go" > pkg/k8s/slim/k8s/apis/labels/selector.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/validation/validation.go" > pkg/k8s/slim/k8s/apis/meta/v1/validation/validation.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/doc.go" > pkg/k8s/slim/k8s/apis/meta/v1/doc.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/helpers.go" > pkg/k8s/slim/k8s/apis/meta/v1/helpers.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/meta.go" > pkg/k8s/slim/k8s/apis/meta/v1/meta.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/register.go" > pkg/k8s/slim/k8s/apis/meta/v1/register.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/time.go" > pkg/k8s/slim/k8s/apis/meta/v1/time.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/time_proto.go" > pkg/k8s/slim/k8s/apis/meta/v1/time_proto.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/types.go" > pkg/k8s/slim/k8s/apis/meta/v1/types.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1beta1/doc.go" > pkg/k8s/slim/k8s/apis/meta/v1beta1/doc.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1beta1/register.go" > pkg/k8s/slim/k8s/apis/meta/v1beta1/register.go
curl "${url}/staging/src/k8s.io/apimachinery/pkg/apis/meta/v1beta1/types.go" > pkg/k8s/slim/k8s/apis/meta/v1beta1/types.go

curl "${url}/staging/src/k8s.io/api/networking/v1/doc.go" > pkg/k8s/slim/k8s/api/networking/v1/doc.go
curl "${url}/staging/src/k8s.io/api/networking/v1/register.go" > pkg/k8s/slim/k8s/api/networking/v1/register.go
curl "${url}/staging/src/k8s.io/api/networking/v1/types.go" > pkg/k8s/slim/k8s/api/networking/v1/types.go
curl "${url}/staging/src/k8s.io/api/networking/v1/well_known_annotations.go" > pkg/k8s/slim/k8s/api/networking/v1/well_known_annotations.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/selection/operator.go" > pkg/k8s/slim/k8s/apis/selection/operator.go

curl "${url}/staging/src/k8s.io/apimachinery/pkg/util/intstr/intstr.go" > pkg/k8s/slim/k8s/apis/util/intstr/intstr.go
```

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
