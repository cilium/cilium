
# Control-plane test for NodePort and HostPort services

This test case checks that NodePort and HostPort load-balancer map entries are
created when a service for NodePort and a pod with hostPort is created.

The test inputs, 'vX.XX/init.yaml' and 'vX.XXX/state1.yaml' were generated using
the 'generate.sh' script.
