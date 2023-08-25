.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _install_kvstore:

Key-Value Store
===============

+---------------------+--------------------------------------+----------------------+
| Option              | Description                          | Default              |
+---------------------+--------------------------------------+----------------------+
| --kvstore TYPE      | Key Value Store Type:                |                      |
|                     | (consul, etcd)                       |                      |
+---------------------+--------------------------------------+----------------------+
| --kvstore-opt OPTS  |                                      |                      |
+---------------------+--------------------------------------+----------------------+

etcd
----

When using etcd, one of the following options need to be provided to configure the
etcd endpoints:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| etcd.address        | Address | Address of etcd endpoint                          |
+---------------------+---------+---------------------------------------------------+
|                     |         | When set to true, Cilium will resolve the domain  |
| etcd.operator       | Boolean | name of the etcd server from the associated k8s   |
|                     |         | service deployed.                                 |
+---------------------+---------+---------------------------------------------------+
| etcd.config         | Path    | Path to an etcd configuration file.               |
+---------------------+---------+---------------------------------------------------+

Example of the etcd configuration file:

.. code-block:: yaml

    ---
    endpoints:
    - https://192.168.0.1:2379
    - https://192.168.0.2:2379
    trusted-ca-file: '/var/lib/cilium/etcd-ca.pem'
    # In case you want client to server authentication
    key-file: '/var/lib/cilium/etcd-client.key'
    cert-file: '/var/lib/cilium/etcd-client.crt'

