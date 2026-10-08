# Versioning and Branching in controller-runtime

We follow the [common KubeBuilder versioning guidelines][guidelines], and
use the corresponding tooling.

For the purposes of the aforementioned guidelines, controller-runtime
counts as a "library project", but otherwise follows the guidelines
exactly.

We stick to a major version of zero and create a minor version for
each Kubernetes minor version and we allow breaking changes in our
minor versions. We create patch releases as needed and don't allow
breaking changes in them.

Publishing a non-zero major version is pointless for us, as the k8s.io/*
libraries we heavily depend on do breaking changes but use the same
versioning scheme as described above. Consequently, a project can only
ever depend on one controller-runtime version.

[guidelines]: https://sigs.k8s.io/kubebuilder-release-tools/VERSIONING.md

## Compatibility and Release Support

For release branches, we generally tend to support backporting one (1)
major release (`release-{X-1}` or `release-0.{Y-1}`), but may go back
further if the need arises and is very pressing (e.g. security updates).

### Dependency Support

Note the [guidelines on dependency versions][dep-versions].  Particularly:

- We **DO** guarantee Kubernetes REST API compatibility -- if a given
  version of controller-runtime stops working with what should be
  a supported version of Kubernetes, this is almost certainly a bug.

- We **DO NOT** guarantee any particular compatibility matrix between
  kubernetes library dependencies (client-go, apimachinery, etc); Such
  compatibility is infeasible due to the way those libraries are versioned.

[dep-versions]: https://sigs.k8s.io/kubebuilder-release-tools/VERSIONING.md#kubernetes-version-compatibility
