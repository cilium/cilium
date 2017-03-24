Getting Started Guide
=====================

This document serves as the easiest introduction to Cilium.   It is a detailed walk through
of getting a single-node Cilium + Docker environment running on your laptop.
It is designed to take 15-30 minutes.

The tutorial leverages Vagrant, and as such should run on any operating system supported
by Vagrant, including Linux, MacOS X, and Windows.   The VM running Docker + Cilium requires
about 3 GB of RAM, so if you laptop has limited resources, you may want to close other memory
hungry applications.

The best way to get help if you get stuck is to ask a question on the
`Cilium Slack channel <https://cilium.herokuapp.com>`_ .  With Cilium contributors
accross the globe, there's almost alway someone available to help.

Step 0: Install Vagrant
-----------------------

If you don't already have Vagrant installed, follow the
`Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_


Step 1: Download the Cilium Source Code
---------------------------------------

Download the latest Cilium `source code <https://github.com/cilium/cilium/archive/master.zip>`_ and unzip the files.

Alternatively, if you are a developer, feel free to use Git to clone the repo:

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

Step 5: Start an Example Service with Docker
--------------------------------------------

Cilium integrates with local container runtimes, which in the case of this demo means Docker.
With Docker, native networking is handled via a component called libnetwork. In order to steer
Docker to request networking of a container from Cilium, a container must be
started with a network of driver type "cilium". Typically you would have to
create such a network first, but for this tutorial, the network comes pre-created.

You can confirm this by running:

::

   $ docker network list

You should see a list of networks, one of which has both name and type of "cilium"

::

    NETWORK ID          NAME                DRIVER              SCOPE
    7b7eda65f9be        bridge              bridge              local
    5eb7c141df2f        cilium              cilium              local
    b0e3e0474e6b        host                host                local
    17c585e7b5b0        none                null                local

So you can now simply launch your first container right away:

::

    $ docker run -d --name service1-instance1 --net cilium -l "id.service1" httpd
    e5723edaa2a1307e7aa7e71b4087882de0250973331bc74a37f6f80667bc5856


This has launched a container running an HTTP server which Cilium is now
managing as an `endpoint`. A Cilium endpoint is one or more application
containers which can be addressed by an individual IP address.


Step 6: Apply an L3/L4 Policy With Cilium
--------------------------------------------

For security purposes though, Cilium let's you not worry about IP addresses.  Instead, you can
use the labels assigned to the VM to define security policies, which are automatically applied to
any container with that label, no matter where or when it is run within a container cluster.  In
this case, we simply give the label "id.service1" to identify any containers that are part of service1.

We'll start with an overly simple example where we just want some containers of another service "service2" to
be able to reach "service1", but not containers from any other service.  Additionally, we only want to allow
service1 to be reachable on port 80, but no other ports.  This is a simple policy that filters only on IP address
(network layer 3) and TCP port (network layer 4), so it is often referred to as an L3/L4 network security policy.


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

Save this JSON to a file name l3_l4_policy.json in your VM, and apply the policy by running:

::

  $ cilium policy import l3_l4_policy.json


Step 7: Test L3/L4 Policy
-------------------------

You can now launch additional containers represent other services attempting to access service1.
Any new container with label "id.service2" will be allowed to access service1 on port 80, otherwise
the network request will be dropped.

To test this out, we'll make an HTTP request to Service1 from a container with the label "id.service2" :

::

    $ docker run --rm -ti --net cilium -l "id.service2" tgraf/netperf ping service1-instance1
    PING service1-instance1 (10.11.250.189): 56 data bytes
    64 bytes from 10.11.250.189: seq=4 ttl=64 time=0.100 ms
    64 bytes from 10.11.250.189: seq=5 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=6 ttl=64 time=0.070 ms
    64 bytes from 10.11.250.189: seq=7 ttl=64 time=0.084 ms
    64 bytes from 10.11.250.189: seq=8 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=9 ttl=64 time=0.103 ms

End the pinging and destroy the container by typing Control-C .

We can see that this request was successful, as we get a valid ping responses.

Now let's run the same ping request to Service1 from a container that does not have that label:

::

    $ docker run --rm -ti --net cilium tgraf/netperf ping service1-instance1

You will see no ping replies, as all requests are dropped by the Cilium security policy.

So with this we see Cilium's ability to segment containers based purely on a container-level
identity label.  This means that the end user can apply security policies without knowing
anything about the IP address of the container IP or requiring some complex mechanism to ensure
that containers of a particular service are assigned an IP address in a particular range.


Step 8:  Apply and Test an L7 Policy with Cilium
------------------------------------------------

In the simple scenario above, it was sufficient to either give a service full access to Service1's API
or no access at all.   But to provide the strongest security (i.e., enforce least-privilege isolation)
between microservices, each service that calls Service1's API should be limited to making only the set
of HTTP requests it requires for legitimate operation.

For example, consider a scenario where Service1 has two API calls:
 * GET /public
 * GET /private

Continuing with the example from above, if Service2 requires access only to the GET /public API call,
the L3/L4 policy along has no visibility into the HTTP requests, and therefore would allow any HTTP request
from Service2 (since all HTTP is over port 80).

To see this, run:

::

    $ docker run --rm -ti --net cilium -l "id.service2" tgraf/netperf curl -si 'http://service1-instance1/public'

and

::

    $ docker run --rm -ti --net cilium -l "id.service2" tgraf/netperf curl -si 'http://service1-instance1/private'

Both return HTTP 404 errors, indicating that the requests were allowed to reach the API services (FIXME: we need a container image
that actually responds on these URLs).

Cilium is capable of enforcing HTTP-layer (i.e., L7) policies to limit what URLs Service2 is allowed to reach.  Here is an
example policy file that extends our original policy by limiting Service2 to making only a GET /public API call, but disallowing
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

    $ docker run --rm -ti --net cilium -l "id.service2" tgraf/netperf curl -si 'http://service1-instance1/public'

and

::

    $ docker run --rm -ti --net cilium -l "id.service2" tgraf/netperf curl -si 'http://service1-instance1/private'

FIXME:  both requests return with no output.  So this is not working as expected.

Step 9: Clean-Up
---------------

When you are done with the setup and want to tear-down the Cilium + Docker VM, open a terminal, cd to the cilium directory
and run:

::

    $ vagrant destroy cilium-master

You can always re-create the VM using the steps described above.





