First Steps
===========

The easiest way to make your first steps with Cilium is to use the following
tutorial which will guide you in setting up Cilium inside a Ubuntu based VM
using vagrant_.

If you are looking for more advanced guides right away, use one of the
following to get you started:

- TBD
- TBD

Step 1: Vagrant Setup
---------------------

The script ``contrib/vagrant/start.sh`` will setup a vagrant_ VM, install
Cilium, and run Cilium as a system service for you. Simply run the following
command to get started:

::

    $ contrib/vagrant/start.sh

After the script has successfully completed, you can log into the VM using
``vagrant ssh``:

::

    $ vagrant ssh


Step 2: Cilium Agent
--------------------

The Cilium agent is now running as a system service and you can interact with
it using the ``cilium`` client. Check the status of the agent by running
``cilium status``:

::

    $ cilium status
    KVStore:            Ok
    ContainerRuntime:   Ok
    Kubernetes:         Disabled
    Cilium:             Ok

The status indicates that all components are operational with the Kubernetes
integration currently being disabled.

Step 3: Docker Containers
-------------------------

Cilium integrates with local container runtimes. The vagrant box used in this
tutorial comes with Docker installed.  In the case of Docker, the native way
of handling networking is via a component called libnetwork. In order to steer
Docker to request networking of a container from Cilium, a container must be
started with a network of driver type "cilium". Typically you would have to
create such a network first, for this tutorial, the network comes pre created
and you can simply launch your first container right away:

::

    $ docker run -d --name  --net cilium httpd
    e5723edaa2a1307e7aa7e71b4087882de0250973331bc74a37f6f80667bc5856

This has launched a container running an HTTP server which Cilium is now
managing as an `endpoint`. A Cilium endpoint is one or more application
containers which can be addressed by an individual IP address.

::

    $ cilium endpoint list
    ENDPOINT   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS
    173        259        no labels                     f00d::a00:20f:0:ad   10.15.148.173   ready

An endpoint is assigned both an IPv4 and IPv6 address, both can be used
interchangeably.

You can now launch a second container and it will be able to reach the
the first container via its IP address:

::

    $ docker run --rm -ti --net cilium tgraf/netperf curl -si 'http://[f00d::a00:20f:0:ad]/'
    HTTP/1.1 200 OK
    Date: Tue, 14 Mar 2017 05:10:34 GMT
    Server: Apache/2.4.25 (Unix)
    Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
    ETag: "2d-432a5e4a73a80"
    Accept-Ranges: bytes
    Content-Length: 45
    Content-Type: text/html

    <html><body><h1>It works!</h1></body></html>


.. _vagrant: https://www.vagrantup.com/
