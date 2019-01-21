.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _gsg_mesos:

**************************
Cilium with Mesos/Marathon
**************************

This tutorial leverages Vagrant and VirtualBox to deploy Apache Mesos, Marathon
and Cilium. You will run Cilium to apply a simple policy between a simulated
web-service and clients. This tutorial can be run on any operating system
supported by Vagrant including Linux, macOS, and Windows.

For more information on Apache Mesos and Marathon orchestration, check out the
`Mesos <https://github.com/apache/mesos>`_ and `Marathon
<https://mesosphere.github.io/marathon/>`_ GitHub pages, respectively.

Step 0: Install Vagrant
=======================

You need to run at least Vagrant version 1.8.3 or you will run into issues
booting the Ubuntu 17.04 base image. You can verify by running ``vagrant
--version``.

If you don't already have Vagrant installed, follow the
`Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_
or see `Download Vagrant <https://www.vagrantup.com/downloads.html>`_ for newer versions.


Step 1: Download the Cilium Source Code
=======================================

Download the latest Cilium `source code <https://github.com/cilium/cilium/archive/master.zip>`_
and unzip the files.

Alternatively, if you are a developer, feel free to clone the repository:

::

    $ git clone https://github.com/cilium/cilium

Step 2: Starting a VM with Cilium
=================================

Open a terminal and navigate into the top of the ``cilium`` source directory.

Then navigate into ``examples/mesos`` and run ``vagrant up``:

::

    $ cd examples/mesos
    $ vagrant up

The script usually takes a few minutes depending on the speed of your internet
connection. Vagrant will set up a VM, install Mesos & Marathon, run Cilium with
the help of Docker compose, and start up the Mesos master and slave services.
When the script completes successfully, it will print:

::

    ==> default: Creating cilium-kvstore
    Creating cilium-kvstore ... done
    ==> default: Creating cilium ... 
    ==> default: Creating cilium
    Creating cilium ... done
    ==> default: Installing loopback driver...
    ==> default: Installing cilium-cni to /host/opt/cni/bin/ ...
    ==> default: Installing new /host/etc/cni/net.d/00-cilium.conf ...
    ==> default: Deploying Vagrant VM + Cilium + Mesos...done 
    $

If the script exits with an error message, do not attempt to proceed with the
tutorial, as later steps will not work properly.   Instead, contact us on the
`Cilium Slack channel <https://cilium.herokuapp.com>`_.

Step 3: Accessing the VM
========================

After the script has successfully completed, you can log into the VM using
``vagrant ssh``:

::

    $ vagrant ssh


All commands for the rest of the tutorial below should be run from inside this
Vagrant VM.  If you end up disconnecting from this VM, you can always reconnect
by going to the ``examples/mesos`` directory and then running the command ``vagrant ssh``.

Step 4: Confirm that Cilium is Running
======================================

The Cilium agent is now running and you can interact with it using the
``cilium`` CLI client. Check the status of the agent by running ``cilium
status``:

::

    $ cilium status
    KVStore:                Ok         Consul: 172.18.0.2:8300
    ContainerRuntime:       Ok         docker daemon: OK
    Kubernetes:             Disabled
    Cilium:                 Ok         OK
    NodeMonitor:            Disabled
    Cilium health daemon:   Ok
    IPv4 address pool:      3/65535 allocated
    IPv6 address pool:      2/65535 allocated
    Controller Status:      10/10 healthy
    Proxy Status:           OK, ip 10.15.0.1, port-range 10000-20000
    Cluster health:   1/1 reachable   (2018-06-19T15:10:28Z)

The status indicates that all necessary components are operational.

Step 5: Run Script to Start Marathon
====================================

Start Marathon inside the Vagrant VM:

::

    $ ./start_marathon.sh
    Starting marathon...
    ...
    ...
    ...
    ...
    Done

Step 6: Simulate a Web-Server and Clients
=========================================

Use ``curl`` to submit a task to Marathon for scheduling, with data to run the
simulated web-server provided by the ``web-server.json``. The web-server simply
responds to requests on a particular port. 

::

    $ curl -i -H 'Content-Type: application/json' -d @web-server.json 127.0.0.1:8080/v2/apps

You should see output similar to the following:

::

    HTTP/1.1 201 Created
    ...
    Marathon-Deployment-Id: [UUID]
    ...

Confirm that Cilium sees the new workload. The output should return the
endpoint with label ``mesos:id=web-server`` and the assigned IP:

::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS
               ENFORCEMENT        ENFORCEMENT
    20928      Disabled           Disabled          59281      mesos:id=web-server           f00d::a0f:0:0:51c0   10.15.137.206   ready
    23520      Disabled           Disabled          4          reserved:health               f00d::a0f:0:0:5be0   10.15.162.64    ready

Test the web-server provides OK output:

::    

    $ export WEB_IP=`cilium endpoint list | grep web-server | awk '{print $7}'`
    $ curl $WEB_IP:8181/api
    OK


Run a script to create two client tasks ("good client" and "bad client") that
will attempt to access the web-server. The output of these tasks will be used
to validate the Cilium network policy enforcement later in the exercise. The
script will generate ``goodclient.json`` and ``badclient.json`` files for the
client tasks, respectively:

::

    $ ./generate_client_file.sh goodclient
    $ ./generate_client_file.sh badclient


Then submit the client tasks to Marathon, which will generate ``GET /public`` and ``GET /private`` requests:

::

    $ curl -i -H 'Content-Type: application/json' -d @goodclient.json 127.0.0.1:8080/v2/apps
    $ curl -i -H 'Content-Type: application/json' -d @badclient.json 127.0.0.1:8080/v2/apps

You can observe the newly created endpoints in Cilium, similar to the following output:

::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS
               ENFORCEMENT        ENFORCEMENT
    20928      Disabled           Disabled          59281      mesos:id=web-server           f00d::a0f:0:0:51c0   10.15.137.206   ready
    23520      Disabled           Disabled          4          reserved:health               f00d::a0f:0:0:5be0   10.15.162.64    ready
    37835      Disabled           Disabled          15197      mesos:id=goodclient           f00d::a0f:0:0:93cb   10.15.152.208   ready
    51053      Disabled           Disabled          5113       mesos:id=badclient            f00d::a0f:0:0:c76d   10.15.34.97     ready

Marathon runs the tasks as batch jobs with ``stdout`` logged to task-specific
files located in ``/var/lib/mesos``. To simplify the retrieval of the
``stdout`` log, use the ``tail_client.sh`` script to output each of the client
logs. In a new terminal, go to ``examples/mesos``, start a new ssh session to
the Vagrant VM with ``vagrant ssh`` and tail the *goodclient* logs:

::

    $ ./tail_client.sh goodclient

and in a separate terminal, do the same thing with ``vagrant ssh`` and observe the *badclient* logs:

::

    $ ./tail_client.sh badclient

Make sure both tail logs continuously prints the result of the clients accessing the */public* and */private* API of the web-server:

::

     ...
     ---------- Test #X  ----------
        Request:   GET /public
        Reply:     OK
      
        Request:   GET /private
        Reply:     OK
     -------------------------------
     ...

Note that both clients are able to access the web-server and retrieve both URLs because no Cilium policy has been applied yet.

Step 7: Apply L3/L4 Policy with Cilium
======================================

Apply an L3/L4 policy only allowing the *goodclient* to access the *web-server*. The L3/L4 json policy looks like:

.. literalinclude:: ../../examples/policies/getting-started/l3-l4-policy.json

In your original terminal session, use ``cilium`` CLI to apply the L3/L4 policy above, saved in the ``l3-l4-policy.json`` file on the VM:
 
::

    $ cilium policy import l3-l4-policy.json
    Revision: 1

**L3/L4 Policy with Cilium and Mesos**

.. image:: images/cilium_mesos_demo_l3-l4-policy-170817.png

You can observe that the policy is applied via ``cilium`` CLI as the *POLICY ENFORCEMENT* column changed from *Disabled* to *Enabled*:

::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS
               ENFORCEMENT        ENFORCEMENT
    20928      Enabled            Disabled          59281      mesos:id=web-server           f00d::a0f:0:0:51c0   10.15.137.206   ready
    23520      Disabled           Disabled          4          reserved:health               f00d::a0f:0:0:5be0   10.15.162.64    ready
    37835      Disabled           Disabled          15197      mesos:id=goodclient           f00d::a0f:0:0:93cb   10.15.152.208   ready
    51053      Disabled           Disabled          5113       mesos:id=badclient            f00d::a0f:0:0:c76d   10.15.34.97     ready

You should also observe that the *goodclient* logs continue to output the *web-server* responses, whereas the *badclient* request does not reach the *web-server* because of policy enforcement, and logging output similar to below. 

::

    ...
    ---------- Test #X  ----------
       Request:   GET /public
       Reply:     Timeout!
     
       Request:   GET /private
       Reply:     Timeout!
    -------------------------------
    ...

Remove the L3/L4 policy in order to give *badclient* access to the *web-server* again.

::

    $ cilium policy delete --all
    Revision: 2

The *badclient* logs should resume outputting the *web-server*'s response and Cilium is configured to no longer enforce policy:

::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS
               ENFORCEMENT        ENFORCEMENT
    29898      Disabled           Disabled          37948      reserved:health               f00d::a0f:0:0:74ca   10.15.242.54   ready
    33115      Disabled           Disabled          38072      mesos:id=web-server           f00d::a0f:0:0:815b   10.15.220.6    ready
    38061      Disabled           Disabled          46430      mesos:id=badclient            f00d::a0f:0:0:94ad   10.15.0.173    ready
    64189      Disabled           Disabled          31645      mesos:id=goodclient           f00d::a0f:0:0:fabd   10.15.152.27   ready

Step 8: Apply L7 Policy with Cilium
===================================

Now, apply an L7 Policy that only allows access for the *goodclient* to the */public* API, included in the ``l7-policy.json`` file:

.. literalinclude:: ../../examples/policies/getting-started/l7-policy.json

Apply using ``cilium`` CLI:

::

    $ cilium policy import l7-policy.json
    Revision: 3

**L7 Policy with Cilium and Mesos**

.. image:: images/cilium_mesos_demo_l7-policy-230817.png

In the terminal sessions tailing the *goodclient* and *badclient* logs, check the *goodclient*'s log to see that */private* is no longer accessible, and the *badclient*'s requests are the same results as the enforced policy in the previous step.

::

    ...
    ---------- Test #X  ----------
       Request:   GET /public
       Reply:     OK
 
       Request:   GET /private
       Reply:     Access Denied
    -------------------------------
    ...

(optional) Remove the policy and notice that the access to */private* is unrestricted again:

::

    $ cilium policy delete --all
    Revision: 4

Step 9: Clean-Up 
================

Exit the vagrant VM by typing ``exit`` in original terminal session. When you want to tear-down the Cilium + Mesos VM and destroy all local state (e.g., the VM disk image), ensure you are in the ``cilium/examples/mesos`` directory and type:

::

    $ vagrant destroy 

You can always re-create the VM using the steps described above.

If instead you just want to shut down the VM but may use it later,
``vagrant halt default`` will work, and you can start it again later.

Troubleshooting
===============

For assistance on any of the Getting Started Guides, please reach out and ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.
