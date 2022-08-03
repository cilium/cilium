
# Control-plane test for k8s Network Policies

This test case checks that upstream k8s NetworkPolicies are created and mapped
correctly to Cilium policy internal representation.

The test inputs, 'vX.XX/init.yaml' and 'vX.XXX/state1.yaml' were generated using
the 'generate.sh' script.
