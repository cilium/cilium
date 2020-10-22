.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gsg_docker:

*******************************
Cilium with Docker & libnetwork
*******************************

This tutorial leverages Vagrant and VirtualBox, thus should run on any
operating system supported by Vagrant, including Linux, macOS, and Windows.

Step 0: Install Vagrant
=======================

If you don't already have Vagrant installed, refer to the :ref:`dev_guide` for
links to installation instructions for Vagrant.

Step 1: Download the Cilium Source Code
=======================================

Download the latest Cilium `source code <https://github.com/cilium/cilium/archive/master.zip>`_
and unzip the files.

Alternatively, if you are a developer, feel free to clone the repository:

::

    $ git clone https://github.com/cilium/cilium

Step 2: Starting the Docker + Cilium VM
=======================================

Open a terminal and navigate into the top of the ``cilium`` source directory.

Then navigate into ``examples/getting-started`` and run ``vagrant up``:

::

    $ cd examples/getting-started
    $ vagrant up

The script usually takes a few minutes depending on the speed of your internet
connection. Vagrant will set up a VM, install the Docker container runtime and
run Cilium with the help of `Docker Compose`_. When the script completes successfully,
it will print:

::

    ==> default: Creating cilium-kvstore
    ==> default: Creating cilium
    ==> default: Creating cilium-docker-plugin
    $

By default the script will deploy Cilium ``1.9`` but it's possible to specify a
different version with the ``CILIUM_VERSION`` environment variable.

For example, the following command will start Vagrant with Cilium ``1.x``:

::

    $ CILIUM_VERSION=v1.x vagrant up

If the script exits with an error message, do not attempt to proceed with the
tutorial, as later steps will not work properly.   Instead, contact us on the
`Cilium Slack channel`_.

.. _`Docker Compose`: https://docs.docker.com/compose/
.. _Cilium Slack channel: https://cilium.herokuapp.com

Step 3: Accessing the VM
========================

After the script has successfully completed, you can log into the VM using
``vagrant ssh``:

::

    $ vagrant ssh


All commands for the rest of the tutorial below should be run from inside this
Vagrant VM.  If you end up disconnecting from this VM, you can always reconnect
in a new terminal window just by running ``vagrant ssh`` again from the Cilium
directory.


Step 4: Confirm that Cilium is Running
======================================

The Cilium agent is now running as a system service and you can interact with
it using the ``cilium`` CLI client. Check the status of the agent by running
``cilium status``:

::

    $ cilium status
    KVStore:                Ok         Consul: 172.18.0.2:8300
    Kubernetes:             Disabled
    Cilium:                 Ok         OK
    NodeMonitor:            Disabled
    Cilium health daemon:   Ok
    IPAM:                   IPv4: 3/65535 allocated from 10.15.0.0/16,
    BandwidthManager:       Disabled
    Masquerading:           IPTables
    Controller Status:      21/21 healthy
    Proxy Status:           OK, ip 10.15.55.93, 1 redirects active on ports 10000-20000
    Hubble:                 Disabled
    Cluster health:         1/1 reachable   (2020-10-22T12:09:24Z)

The status indicates that all components are operational with the Kubernetes
integration currently being disabled.

Step 5: Create a Docker Network of Type Cilium
==============================================

Cilium integrates with local container runtimes, which in the case of this demo
means Docker. With Docker, native networking is handled via a component called
libnetwork. In order to steer Docker to request networking of a container from
Cilium, a container must be started with a network of driver type "cilium".

With Cilium, all containers are connected to a single logical network, with
isolation added not based on IP addresses but based on container labels (as we
will do in the steps below). So with Docker, we simply create a single network
named 'cilium-net' for all containers:

::

    $ docker network create --driver cilium --ipam-driver cilium cilium-net


Step 6: Start an Example Service with Docker
============================================

In this tutorial, we'll use a container running a simple HTTP server to
represent a microservice application which we will refer to as *app1*.  As a result, we
will start this container with the label "id=app1", so we can create Cilium
security policies for that service.

Use the following command to start the *app1* container connected to the
Docker network managed by Cilium:

::

    $ docker run -d --name app1 --net cilium-net -l "id=app1" cilium/demo-httpd
    e5723edaa2a1307e7aa7e71b4087882de0250973331bc74a37f6f80667bc5856


This has launched a container running an HTTP server which Cilium is now
managing as an :ref:`endpoint`. A Cilium endpoint is one or more application
containers which can be addressed by an individual IP address.


Step 7: Apply an L3/L4 Policy With Cilium
=========================================

When using Cilium, endpoint IP addresses are irrelevant when defining security
policies.  Instead, you can use the labels assigned to the VM to define
security policies, which are automatically applied to any container with that
label, no matter where or when it is run within a container cluster.

We'll start with an overly simple example where we create two additional
apps, *app2* and *app3*, and we want *app2* containers to be able
to reach *app1* containers, but *app3* containers should not be allowed
to reach *app1* containers.  Additionally, we only want to allow *app1*
to be reachable on port 80, but no other ports.  This is a simple policy that
filters only on IP address (network layer 3) and TCP port (network layer 4), so
it is often referred to as an L3/L4 network security policy.

Cilium performs stateful ''connection tracking'', meaning that if a policy allows
*app2* to contact *app1*, it will automatically allow return
packets that are part of *app1* replying to *app2* within the context
of the same TCP/UDP connection.

**L4 Policy with Cilium and Docker**

.. image:: images/cilium_dkr_demo_l3-l4-policy-170817.png

We can achieve that with the following Cilium policy:

.. literalinclude:: ../../examples/policies/getting-started/cilium_dkr_demo_l3-l4-policy-170817.json

Save this JSON to a file named l3_l4_policy.json in your VM, and apply the
policy by running:

::

  $ cilium policy import l3_l4_policy.json
  Revision: 2


Step 8: Test L3/L4 Policy
=========================


You can now launch additional containers that represent other services attempting to
access *app1*. Any new container with label "id=app2" will be allowed
to access *app1* on port 80, otherwise the network request will be dropped.

To test this out, we'll make an HTTP request to *app1* from a container
with the label "id=app2" :

::

    $ docker run --rm -ti --net cilium-net -l "id=app2" cilium/demo-client curl -m 20 http://app1
    <html><body><h1>It works!</h1></body></html>

We can see that this request was successful, as we get a valid HTTP response.

Now let's run the same HTTP request to *app1* from a container that has
label "id=app3":

::

    $ docker run --rm -ti --net cilium-net -l "id=app3" cilium/demo-client curl -m 10 http://app1

You will see no reply as all packets are dropped by the Cilium security policy.
The request will time-out after 10 seconds.

So with this we see Cilium's ability to segment containers based purely on a
container-level identity label.  This means that the end user can apply
security policies without knowing anything about the IP address of the
container or requiring some complex mechanism to ensure that containers of a
particular service are assigned an IP address in a particular range.


Step 9:  Apply and Test an L7 Policy with Cilium
================================================

In the simple scenario above, it was sufficient to either give *app2* /
*app3* full access to *app1's* API or no access at all.   But to
provide the strongest security (i.e., enforce least-privilege isolation)
between microservices, each service that calls *app1's* API should be
limited to making only the set of HTTP requests it requires for legitimate
operation.

For example, consider a scenario where *app1* has two API calls:
 * GET /public
 * GET /private

Continuing with the example from above, if *app2* requires access only to
the GET /public API call, the L3/L4 policy alone has no visibility into the
HTTP requests, and therefore would allow any HTTP request from *app2*
(since all HTTP is over port 80).

To see this, run:

::

    $ docker run --rm -ti --net cilium-net -l "id=app2" cilium/demo-client curl 'http://app1/public'
    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id=app2" cilium/demo-client curl 'http://app1/private'
    { 'val': 'this is private' }

Cilium is capable of enforcing HTTP-layer (i.e., L7) policies to limit what
URLs *app2* is allowed to reach.  Here is an example policy file that
extends our original policy by limiting *app2* to making only a GET /public
API call, but disallowing all other calls (including GET /private).

**L7 Policy with Cilium and Docker**

.. image:: images/cilium_dkr_demo_l7-policy-230817.png

The following Cilium policy file achieves this goal:

.. literalinclude:: ../../examples/policies/getting-started/cilium_dkr_demo_l7-policy-230817.json

Create a file with this contents and name it l7_aware_policy.json. Then
import this policy to Cilium by running:

::

  $ cilium policy delete --all
  Revision: 3
  $ cilium policy import l7_aware_policy.json
  Revision: 4

::

    $ docker run --rm -ti --net cilium-net -l "id=app2" cilium/demo-client curl -si 'http://app1/public'
    HTTP/1.1 200 OK
    Accept-Ranges: bytes
    Content-Length: 28
    Date: Tue, 31 Oct 2017 14:30:56 GMT
    Etag: "1c-54bb868cec400"
    Last-Modified: Mon, 27 Mar 2017 15:58:08 GMT
    Server: Apache/2.4.25 (Unix)
    Content-Type: text/plain; charset=utf-8

    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id=app2" cilium/demo-client curl -si 'http://app1/private'
    HTTP/1.1 403 Forbidden
    Content-Type: text/plain; charset=utf-8
    X-Content-Type-Options: nosniff
    Date: Tue, 31 Oct 2017 14:31:09 GMT
    Content-Length: 14

    Access denied

As you can see, with Cilium L7 security policies, we are able to permit
*app2* to access only the required API resources on *app1*, thereby
implementing a "least privilege" security approach for communication between
microservices.

We hope you enjoyed the tutorial.  Feel free to play more with the setup, read
the rest of the documentation, and reach out to us on the `Cilium
Slack channel`_ with any questions!


Step 10: Clean-Up
=================

Exit the vagrant VM by typing ``exit``.

When you are done with the setup and want to tear-down the Cilium + Docker VM,
and destroy all local state (e.g., the VM disk image), open a terminal in the
cilium/examples/getting-started directory and type:

::

    $ vagrant destroy

You can always re-create the VM using the steps described above.

If instead you just want to shut down the VM but may use it later,
``vagrant halt`` will work, and you can start it again later.
