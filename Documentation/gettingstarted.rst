.. _gs_guide:

Getting Started Guide
=====================

This document serves as the easiest introduction to Cilium.   It is a detailed walk through
of getting a single-node Cilium + Docker environment running on your laptop.
It is designed to take 15-30 minutes.

If you haven't read the :ref:`intro` yet, we'd encourage you to do that first.

The tutorial leverages Vagrant, and as such should run on any operating system supported
by Vagrant, including Linux, MacOS X, and Windows.   The VM running Docker + Cilium requires
about 3 GB of RAM, so if you laptop has limited resources, you may want to close other memory
hungry applications.

The best way to get help if you get stuck is to ask a question on the
`Cilium Slack channel <https://cilium.herokuapp.com>`_ .  With Cilium contributors
across the globe, there is almost always someone available to help.

Step 0: Install Vagrant
-----------------------

.. note::

   You need to run Vagrant version 1.8.3 or later or you will run into issues
   booting the Ubuntu 16.10 base image.

If you don't already have Vagrant installed, follow the
`Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_


Step 1: Download the Cilium Source Code
---------------------------------------

Download the latest Cilium `source code <https://github.com/cilium/cilium/archive/master.zip>`_ and unzip the files.

Alternatively, if you are a developer, feel free to use Git to clone the repository:

::

    $ git clone https://github.com/cilium/cilium

Step 2: Starting the Docker + Cilium VM
---------------------------------------

Open a terminal and cd into the top of the cilium source directory.

The script ``contrib/vagrant/start.sh`` will setup a Vagrant VM, with Docker and Cilium installed
and running as services.  Simply run the following
command to get started:

::

    $ contrib/vagrant/start.sh

The script usually takes a few minutes, but may take much longer if you are on a
slow Internet connection.   When the script completes successfully, it will print:

::

   $ ==> cilium-master: Cilium successfully started!

If the script exits with the following error message, something went wrong:

::

   $ ==> cilium-master: Timeout waiting for Cilium to start...

If this error appears, do not attempt to proceed with the tutorial, as later steps will not
work properly.   Instead, contact us on the `Cilium Slack channel <https://cilium.herokuapp.com>`_ .

Step 3: Accessing the VM
------------------------

After the script has successfully completed, you can log into the VM using
``vagrant ssh``:

::

    $ vagrant ssh


All commands for the rest of the tutorial below should be run from inside this Vagrant VM.
If you end up disconnecting from this VM, you can always reconnect in a new terminal window
just by running ``vagrant ssh`` again.


Step 4: Confirm that Cilium is Running
--------------------------------------

The Cilium agent is now running as a system service and you can interact with
it using the ``cilium`` CLI client. Check the status of the agent by running
``cilium status``:

::

    $ cilium status
    KVStore:            Ok
    ContainerRuntime:   Ok
    Kubernetes:         Disabled
    Cilium:             Ok

The status indicates that all components are operational with the Kubernetes
integration currently being disabled.

Step 5: Create a Docker Network of Type Cilium
----------------------------------------------

Cilium integrates with local container runtimes, which in the case of this demo means Docker.
With Docker, native networking is handled via a component called libnetwork. In order to steer
Docker to request networking of a container from Cilium, a container must be
started with a network of driver type "cilium".

With Cilium, all containers are connected to a single logical network, with isolation
added not based on IP addresses but based on container labels (as we will do in the steps
below).   So with Docker, we simply create a single network named 'cilium-net' for all containers:

::

    $ docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium-net


Step 6: Start an Example Service with Docker
--------------------------------------------

In this tutorial, we'll use a container running a simple HTTP server to represent a microservice
which we will refer to as *Service1*.  As a result, we will start this container with the label
"id.service1", so we can create Cilium security policies for that service.

Use the following command to start the *Service1* container connected to the Docker network managed by Cilium:

::

    $ docker run -d --name service1-instance1 --net cilium-net -l "id.service1" cilium/demo-httpd
    e5723edaa2a1307e7aa7e71b4087882de0250973331bc74a37f6f80667bc5856


This has launched a container running an HTTP server which Cilium is now
managing as an `endpoint`. A Cilium endpoint is one or more application
containers which can be addressed by an individual IP address.


Step 7: Apply an L3/L4 Policy With Cilium
--------------------------------------------

When using Cilium, endpoint IP addresses are irrelevant when defining security policies.  Instead, you can
use the labels assigned to the VM to define security policies, which are automatically applied to
any container with that label, no matter where or when it is run within a container cluster.

We'll start with an overly simple example where we create two additional services, *Service2* and *Service3*,
and we want Service2 containers to be able to reach *Service1* containers, but *Service3* containers should not be
allowed to reach *Service1* containers.  Additionally, we only want to allow
*Service1* to be reachable on port 80, but no other ports.  This is a simple policy that filters only on IP address
(network layer 3) and TCP port (network layer 4), so it is often referred to as an L3/L4 network security policy.

Cilium performs stateful ''connection tracking'', meaning that if policy allows the *Service2* to contact *Service3*,
it will automatically allow return packets that are part of *Service1* replying to *Service2* within the context of the
same TCP/UDP connection.

We can achieve that with the following Cilium policy:

::

  {
      "name": "root",
      "rules": [{
          "coverage": ["id.service1"],
          "allow": ["id.service2"]
      },{
          "coverage": ["id.service1"],
          "l4": [{
              "in-ports": [{ "port": 80, "protocol": "tcp" }]
          }]
      }]
  }

Save this JSON to a file named l3_l4_policy.json in your VM, and apply the policy by running:

::

  $ cilium policy import l3_l4_policy.json


Step 8: Test L3/L4 Policy
-------------------------

You can now launch additional containers represent other services attempting to access *Service1*.
Any new container with label "id.service2" will be allowed to access *Service1* on port 80, otherwise
the network request will be dropped.

To test this out, we'll make an HTTP request to *Service1* from a container with the label "id.service2" :

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client ping service1-instance1
    PING service1-instance1 (10.11.250.189): 56 data bytes
    64 bytes from 10.11.250.189: seq=4 ttl=64 time=0.100 ms
    64 bytes from 10.11.250.189: seq=5 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=6 ttl=64 time=0.070 ms
    64 bytes from 10.11.250.189: seq=7 ttl=64 time=0.084 ms
    64 bytes from 10.11.250.189: seq=8 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=9 ttl=64 time=0.103 ms

We can see that this request was successful, as we get a valid ping responses.

Now let's run the same ping request to *Service1* from a container that has label "id.service3":

::

    $ docker run --rm -ti --net cilium-net -l "id.service3" cilium/demo-client ping service1-instance1

You will see no ping replies, as all requests are dropped by the Cilium security policy.

So with this we see Cilium's ability to segment containers based purely on a container-level
identity label.  This means that the end user can apply security policies without knowing
anything about the IP address of the container or requiring some complex mechanism to ensure
that containers of a particular service are assigned an IP address in a particular range.


Step 9:  Apply and Test an L7 Policy with Cilium
------------------------------------------------

In the simple scenario above, it was sufficient to either give *Service2* / *Service3* full access to *Service1's* API
or no access at all.   But to provide the strongest security (i.e., enforce least-privilege isolation)
between microservices, each service that calls *Service1's* API should be limited to making only the set
of HTTP requests it requires for legitimate operation.

For example, consider a scenario where *Service1* has two API calls:
 * GET /public
 * GET /private

Continuing with the example from above, if *Service2* requires access only to the GET /public API call,
the L3/L4 policy along has no visibility into the HTTP requests, and therefore would allow any HTTP request
from *Service2* (since all HTTP is over port 80).

To see this, run:

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/public'
    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/private'
    { 'val': 'this is private' }

Cilium is capable of enforcing HTTP-layer (i.e., L7) policies to limit what URLs *Service2* is allowed to reach.  Here is an
example policy file that extends our original policy by limiting *Service2* to making only a GET /public API call, but disallowing
all other calls (including GET /private).

::

  {
    "name": "root",
    "rules": [{
        "coverage": ["id.service1"],
        "allow": ["id.service2", "reserved:host"]
    },{
        "coverage": ["id.service2"],
        "l4": [{
            "out-ports": [{
                "port": 80, "protocol": "tcp",
                "redirect": "http",
                "rules": [
                    { "expr": "Method(\"GET\") && Path(\"/public\")" }
                ]
            }]
        }]
    }]
  }

Create a file with this contents and name it l7_aware_policy.json .  Then import this policy to Cilium by running:

::

  $ cilium policy import l7_aware_policy.json

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/public'
    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/private'
    Access denied

As you can see, with Cilium L7 security policies, we are able to permit *Service2* to access only the required API resources on
*Service1*, thereby implementing a "least privilege" security approach for communication between microservices.

We hope you enjoy the tutorial.  Feel free to play more with the setup, read the rest of the documentation, and
feel free to reach out to us on the `Cilium Slack channel <https://cilium.herokuapp.com>`_ with any questions!


Step 10: Clean-Up
-----------------

When you are done with the setup and want to tear-down the Cilium + Docker VM,
and destroy all local state (e.g., the VM disk image), open a terminal, cd to
the cilium directory
and run:

::

    $ vagrant destroy cilium-master

You can always re-create the VM using the steps described above.

If instead you instead just want to shut down the VM but may use it later,
"vagrant halt cilium-master" will work, and you can start it again later
using the contrib/vagrant/start.sh script.

