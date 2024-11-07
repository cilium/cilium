[![Go Report Card](https://goreportcard.com/badge/sigs.k8s.io/controller-runtime)](https://goreportcard.com/report/sigs.k8s.io/controller-runtime)
[![godoc](https://pkg.go.dev/badge/sigs.k8s.io/controller-runtime)](https://pkg.go.dev/sigs.k8s.io/controller-runtime)

# Kubernetes controller-runtime Project

The Kubernetes controller-runtime Project is a set of go libraries for building
Controllers. It is leveraged by [Kubebuilder](https://book.kubebuilder.io/) and
[Operator SDK](https://github.com/operator-framework/operator-sdk). Both are
a great place to start for new projects. See
[Kubebuilder's Quick Start](https://book.kubebuilder.io/quick-start.html) to
see how it can be used.

Documentation:

- [Package overview](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg)
- [Basic controller using builder](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/builder#example-Builder)
- [Creating a manager](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#example-New)
- [Creating a controller](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/controller#example-New)
- [Examples](https://github.com/kubernetes-sigs/controller-runtime/blob/main/examples)
- [Designs](https://github.com/kubernetes-sigs/controller-runtime/blob/main/designs)

# Versioning, Maintenance, and Compatibility

The full documentation can be found at [VERSIONING.md](VERSIONING.md), but TL;DR:

Users:

- We follow [Semantic Versioning (semver)](https://semver.org)
- Use releases with your dependency management to ensure that you get compatible code
- The main branch contains all the latest code, some of which may break compatibility (so "normal" `go get` is not recommended)

Contributors:

- All code PR must be labeled with :bug: (patch fixes), :sparkles: (backwards-compatible features), or :warning: (breaking changes)
- Breaking changes will find their way into the next major release, other changes will go into an semi-immediate patch or minor release
- For a quick PR template suggesting the right information, use one of these PR templates:
  * [Breaking Changes/Features](/.github/PULL_REQUEST_TEMPLATE/breaking_change.md)
  * [Backwards-Compatible Features](/.github/PULL_REQUEST_TEMPLATE/compat_feature.md)
  * [Bug fixes](/.github/PULL_REQUEST_TEMPLATE/bug_fix.md)
  * [Documentation Changes](/.github/PULL_REQUEST_TEMPLATE/docs.md)
  * [Test/Build/Other Changes](/.github/PULL_REQUEST_TEMPLATE/other.md)

## Compatibility

Every minor version of controller-runtime has been tested with a specific minor version of client-go. A controller-runtime minor version *may* be compatible with
other client-go minor versions, but this is by chance and neither supported nor tested. In general, we create one minor version of controller-runtime
for each minor version of client-go and other k8s.io/* dependencies.

The minimum Go version of controller-runtime is the highest minimum Go version of our Go dependencies. Usually, this will
be identical to the minimum Go version of the corresponding k8s.io/* dependencies.

Compatible k8s.io/*, client-go and minimum Go versions can be looked up in our [go.mod](go.mod) file.

|          | k8s.io/*, client-go | minimum Go version |
|----------|:-------------------:|:------------------:|
| CR v0.19 |        v0.31        |        1.22        |
| CR v0.18 |        v0.30        |        1.22        |
| CR v0.17 |        v0.29        |        1.21        |
| CR v0.16 |        v0.28        |        1.20        |
| CR v0.15 |        v0.27        |        1.20        |

## FAQ

See [FAQ.md](FAQ.md)

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

controller-runtime is a subproject of the [kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) project
in sig apimachinery.

You can reach the maintainers of this project at:

- Slack channel: [#controller-runtime](https://kubernetes.slack.com/archives/C02MRBMN00Z)
- Google Group: [kubebuilder@googlegroups.com](https://groups.google.com/forum/#!forum/kubebuilder)

## Contributing

Contributions are greatly appreciated. The maintainers actively manage the issues list, and try to highlight issues suitable for newcomers.
The project follows the typical GitHub pull request model. See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.
Before starting any work, please either comment on an existing issue, or file a new one.

## Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
