
Control-plane tests for the cilium agent
----------------------------------------

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

