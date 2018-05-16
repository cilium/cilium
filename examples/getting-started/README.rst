Getting Started with Vagrant
============================

This is a simple Vagrant environment to experiment with Cilium. To get started,
simply run ``vagrant up`` and then log into the VM with ``vagrant ssh``.

For further instructions, please see the `Getting started guide`_.

.. _Getting started guide: http://cilium.readthedocs.io/en/doc-1.0/gettingstarted/docker

::

    $ vagrant up
    Bringing machine 'cilium-1' up with 'virtualbox' provider...
    [...]
    ==> cilium-1: cilium-kvstore is up-to-date
    ==> cilium-1: Recreating cilium
    ==> cilium-1: Recreating cilium-docker-plugin

    $ vagrant ssh
    Welcome to Ubuntu 16.10 (GNU/Linux 4.8.0-41-generic x86_64)
    [...]

    vagrant@cilium-1:~/cilium/examples/getting-started$ cilium status
    KVStore:            Ok
    ContainerRuntime:   Ok
    Kubernetes:         Disabled
    Cilium:             Ok
