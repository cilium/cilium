
# Control-plane tests for the cilium agent

The control-plane tests are integration tests that validate that the agent
performs the correct datapath action when given Kubernetes resources as inputs.

These tests are one step down from full end-to-end tests and the test cases
are purposely written in terms of "k8s objects in, mock datapath state out" in
order to not make any assumptions about the control-plane implementation. This
approach caters towards:

- Regression testing. Bugs in the control-plane implementation that can
  be reproduced in a k8s environment can be converted into a test case by
  capturing the k8s resources that describe the state of the cluster

- Refactoring. Even large changes in the implementation of the control-plane
  would not invalidate the test cases themselves. Only `suite/agent.go` would need
  to be adapted.

## Running the tests

The tests can be run as usual with Go test:

  $ go test ./test/controlplane

If the test case is a golden test, the golden output files can be updated
with the '-update' flag:

  $ go test ./test/controlplane -test.v -test.run TestControlPlane/GracefulTermination -update

For debug log output, run with '-debug' flag:

  $ go test ./test/controlplane -test.v -debug

## Writing tests

Since the tests pull in pretty much the whole agent the tests are
unidiomatically compiled into a single test binary to avoid long linking
times and producing of many large binaries.  The entry point is defined in
controlplane_test.go, and the tests add themselves into the test suite via
init() by calling suite.AddTestCase.

The test cases consist of calling suite.NewControlPlaneTest to construct
suite.ControlPlaneTest with which one can start the agent with desired
configuration and update and delete K8s objects.

For representative examples see `node/nodehandler.go` (test with manually
constructed k8s object) and `services/nodeport/nodeport.go` (test with
generated k8s objects and golden test files).

