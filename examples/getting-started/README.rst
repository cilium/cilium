Getting Started with Vagrant
============================

This is a simple Vagrant environment to experiment with Cilium. To get started,
simply run ``vagrant up`` and then log into the VM with ``vagrant ssh``.

For further instructions, please see the `Getting started guide`_.

.. _Getting started guide: https://cilium.readthedocs.io/en/latest/gettingstarted/docker

::

    $ vagrant up
    Bringing machine 'default' up with 'virtualbox' provider...
    [...]
    ==> default: cilium-kvstore is up-to-date
    ==> default: Recreating cilium
    ==> default: Recreating cilium-docker-plugin

    $ vagrant ssh
    Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-29-generic x86_64)
    [...]

    vagrant@vagrant:~/cilium/examples/getting-started$ cilium status
    KVStore:                Ok         Consul: 172.18.0.2:8300
    ContainerRuntime:       Ok         docker daemon: OK
    Kubernetes:             Disabled
    Cilium:                 Ok         OK
    NodeMonitor:            Disabled
    Cilium health daemon:   Ok
    IPv4 address pool:      3/65535 allocated
    IPv6 address pool:      2/65535 allocated
    Controller Status:      13/13 healthy
    Proxy Status:           OK, ip 10.15.0.1, port-range 10000-20000
    Cluster health:   1/1 reachable   (2018-12-20T15:06:09Z)

