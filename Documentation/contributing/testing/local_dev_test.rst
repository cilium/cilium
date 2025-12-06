.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _local_dev_test:

Local development & testing
---------------------------

This section provides an overview of how to set up a local development environment for
running tests.

Check Makefile targets such as ``make help``, ``make lint``, ``make test`` to discover repo-specific commands.

#. Run lint checks and static analysis.
#. Run unit tests.
#. Create a local kind cluster that matches the k8s version used in CI.
#. Deploy the project (CLI, Helm, or manifests).
#. Run integration / Ginkgo tests against that cluster.

Tasks & commands
~~~~~~~~~~~~~~~~

Running local lint checks
^^^^^^^^^^^^^^^^^^^^^^^^^
Most repositories provide a ``make`` target to run lint checks.

::

  make lint

  # or run golangci-lint directly (common Go linting tool)
  golangci-lint run ./...

Best practice: run lint checks before tests and fix violations in small commits.

Running unit tests
^^^^^^^^^^^^^^^^^^
Run unit tests across packages with verbose output, the race detector and a coverage profile:

::

  go test ./... -v -race -coverprofile=coverage.out

  # run a single package
  go test ./pkg/somepackage -v

If you have ``make test`` or similar, prefer the project's Make target because it may set necessary environment variables or flags.

Deploying a local kind cluster
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Use ``kind`` to reproduce a Kubernetes environment similar to CI. Replace the node image to match the k8s version used in CI.

::

  kind create cluster --name cilium-dev --image kindest/node:v1.26.3

  # delete when finished
  kind delete cluster --name cilium-dev

If your workflow requires specific kernel features or alternate kernel versions, document how to start kind nodes or use a VM image that matches CI.

Deploying the project locally
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Use the same deployment mechanism used in CI (CLI, Helm chart or manifests). Examples:

::

  helm repo add cilium https://helm.cilium.io/
  helm repo update
  helm install cilium cilium/cilium --namespace kube-system --create-namespace --version <version> -f local-values.yaml

  # or repository-provided Make target
  make kind-deploy

Running the CLI connectivity test
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
After deployment, run the project's CLI connectivity / status checks to confirm the install is healthy.

::

  kubectl -n kube-system get pods
  kubectl -n kube-system logs -l k8s-app=cilium

  ./<project-cli> status
  ./<project-cli> connectivity test

If the project provides ``make test-connectivity`` or an equivalent helper, prefer using that target.

Running Ginkgo integration / conformance tests locally
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If your repo uses Ginkgo for integration/conformance tests, you can run focused suites locally by translating the ``main-focus.yaml`` entries into a ``--focus`` regex.

::

  GINKGO_FOCUS="<regex-from-main-focus>" ginkgo -v --focus "$GINKGO_FOCUS" ./test/ginkgo

  # run tests with a single node to reduce flakiness
  ginkgo -v --nodes=1 --focus "$GINKGO_FOCUS" ./test/ginkgo

Useful flags:

* ``--focus`` — run only tests matching regex
* ``--skip`` — skip matching tests
* ``--nodes=1`` — run serially to avoid concurrency flakiness
* ``-v`` / ``--trace`` — verbose output for debugging

Good practices
~~~~~~~~~~~~~~

* Run lint checks and unit tests before opening a PR.
* Keep focused integration runs small and reproducible (single-node, stable images).
* Mirror CI environment versions locally (k8s, image tags) to reduce surprises.
* Capture logs and pod descriptions immediately when a test fails:

::

  kubectl -n <ns> describe pod <pod-name>
  kubectl -n <ns> logs <pod-name> --all-containers

* If a test is flaky locally but passes in CI, try increasing verbosity and running the failing test in serial.

Troubleshooting & cleanup
~~~~~~~~~~~~~~~~~~~~~~~~~

* Delete the kind cluster if state is corrupted:

::

  kind delete cluster --name cilium-dev

* Common debugging commands:

::

  kubectl get pods -A
  kubectl get events -A --sort-by='.metadata.creationTimestamp'
  kubectl -n kube-system logs -l k8s-app=cilium
