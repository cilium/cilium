BGPv2 Labs
==========

Prerequisites
-------------

Few dependencies are required to run kubernetes kind cluster in container lab environment.

Please refer to installation guides below
- [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/)
- [Container-lab](https://containerlab.dev/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

Usage
-----

Each lab contains a 'Makefile' which can be used to deploy, destroy or reload lab as well as apply kubernetes resources.
- make deploy
- make destroy
- make reload

Version of Cilium in these labs is pinned to v1.16.0. It can be overridden by VERSION environment variable.
