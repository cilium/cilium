.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

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

consul
------

When using consul, the consul agent address needs to be provided with the
``consul.address``:  ``consul.tlsconfig`` is optional, and is only required
for TLS authentication:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| consul.address      | Address | Address of consul agent                           |
+---------------------+---------+---------------------------------------------------+
| consul.tlsconfig    | Path    | Path to a consul configuration file               |
|                     |         | for client server authentication                  |
+---------------------+---------+---------------------------------------------------+

Example of the consul configuration file:

.. code:: yaml

    ---
    cafile: '/var/lib/cilium/consul-ca.pem'
    keyfile: '/var/lib/cilium/client-key.pem'
    certfile: '/var/lib/cilium/client.pem'
    #insecureskipverify: true

etcd
----

When using etcd, one of the following options need to be provided to configure the
etcd endpoints:

+---------------------+---------+---------------------------------------------------+
| Option              |  Type   | Description                                       |
+---------------------+---------+---------------------------------------------------+
| etcd.address        | Address | Address of etcd endpoint                          |
+---------------------+---------+---------------------------------------------------+
| etcd.config         | Path    | Path to an etcd configuration file.               |
+---------------------+---------+---------------------------------------------------+

Example of the etcd configuration file:

.. code:: yaml

    ---
    endpoints:
    - https://192.168.0.1:2379
    - https://192.168.0.2:2379
    trusted-ca-file: '/var/lib/cilium/etcd-ca.pem'
    # In case you want client to server authentication
    key-file: '/var/lib/cilium/etcd-client.key'
    cert-file: '/var/lib/cilium/etcd-client.crt'

