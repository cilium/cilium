
# Control-plane tests for the cilium agent

The control-plane tests are integration tests that validate that the agent
performs the correct datapath action when given Kubernetes resources as inputs.

These tests are one step down from full end-to-end tests and the test cases are
purposely written in terms of "k8s objects in, mock datapath state out" in order to
not make any assumptions about the control-plane implementation. This approach
caters towards:

- Regression testing. Bugs in the control-plane implementation that can
  be reproduced in a k8s environment can be converted into a test case by capturing
  the k8s resources that describe the state of the cluster

- Refactoring. Even large changes in the implementation of the control-plane
  would not invalidate the test cases themselves. Only the "runner" implementations
  would need to adopt to the new internal structure.


## Running the tests

The tests can be run as usual with Go test:

  $ go test ./test/control-plane/...

If the test case is a golden test, the golden output files can be updated
with the '-update' flag:

  $ go test ./test/control-plane/services/dual-stack -test.v -update

For debug log output, run with '-debug' flag:

  $ go test ./test/control-plane/services/... -test.v -debug

## Writing tests

Control-plane test case (ControlPlaneTestCase) consist of steps, with each step
(ControlPlaneTestStep) consisting of a set of input K8s objects and a validation
function that verifies the fake datapath object. Since applying the K8s objects
is asynchronous, the validation is repeated until either timeout is reached or
it passes.

Tests can be written either by manually defining the objects and the validation
of each step or as a golden test case where the input objects are unmarshalled
from YAML files.

For a working example see test/control-plane/services/dual-stack/dualstack_test.go
and follow references up from NewGoldenServicesTest to see how it's constructed
and validated.

