.. _gs_guide:

Getting Started Guide
=====================

This document serves as the easiest introduction to Cilium.   It is a detailed
walk through of getting a single-node Cilium + Docker environment running on
your laptop.  It is designed to take 15-30 minutes.

If you haven't read the :ref:`intro` yet, we'd encourage you to do that first.

Getting Started using Kubernetes
--------------------------------

This guide is using minikube to demonstrate deployment and operation of Cilium
in a Kubernetes cluster. If instead you want to dive right into the details of
deploying Cilium on a full fledged Kubernetes cluster, then go straight to the
<<k8s install ref>>.

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_ .  With Cilium contributors
across the globe, there is almost always someone available to help.

Step 0: Install minikube & kubectl
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install ``kubectl`` as described in the `Kubernetes installation guide
<https://kubernetes.io/docs/tasks/kubectl/install/>`_.

Install ``minikube`` 0.19 as described in the guide `Running Kubernetes Locally
via Minikube
<https://kubernetes.io/docs/getting-started-guides/minikube/#installation>`_.

::

    $ minikube start --network-plugin=cni --iso-url https://github.com/cilium/minikube-iso/raw/master/minikube.iso

.. note:: The ``--iso-url`` is required to run a recent enough kernel. The base
          ISO image of minikube has since been updated in the development
          branch of minikube. As soon as the minikube 0.19 ISO is released,
          passing the ``-iso-url`` parameter will no longer be required.

After minikube has finished  setting up your new Kubernetes cluster, you can
check the status of it by running ``kubectl get cs``:

::

    $ kubectl get cs
    NAME                 STATUS    MESSAGE              ERROR
    controller-manager   Healthy   ok
    scheduler            Healthy   ok
    etcd-0               Healthy   {"health": "true"}

Step 1: Deploy Cilium
^^^^^^^^^^^^^^^^^^^^^

The next step is to deploy Cilium to your Kubernetes cluster in the form of a
DaemonSet_ which will deploy one Cilium pod per cluster node in the
``kube-system`` namespace along with all other system relevant daemons and
services.

To deploy Cilium, run ``kubectl create -f`` and pass in the file ``cilium-ds.yaml``
contained in this directory.

::

    $ kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/minikube/cilium-ds.yaml
    clusterrole "cilium" created
    serviceaccount "cilium" created
    clusterrolebinding "cilium" created
    daemonset "cilium-consul" created
    daemonset "cilium" created

Kubernetes is now deploying the Cilium DaemonSet_ as a pod on all cluster
nodes. This operation is performed in the background. You can run ``kubectl
--namespace kube-system get ds`` to check the progress of the DaemonSet_
deployment.  Notice how the number of pods in the ``READY`` column will start
increasing from 0 to match the number in the ``DESIRED`` column.

::

    $ kubectl get ds --namespace kube-system
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          1         1         1         <none>          2m
    cilium-consul   1         1         1         <none>          2m

Wait until the cilium Deployment shows a ``READY`` count of ``1`` like above.
If this does not happen for some reason, go to the Troubleshooting_ section to
investigate.

Step 2: Restart kube-dns pods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When we ran ``minikube start``, minikube automatically created a Kubernetes
Deployment_ ``kube-dns`` to provide DNS resolution. This deployment was
performed before we deployed Cilium. Because of this, Cilium is not aware of
the ``kube-dns`` pods can thus not reach them. There is an easy fix for this.
Kubernetes automatically restarts pods of a deployment if we delete the pods.
The restarted pods will then be managed by Cilium. If this was a real
deployment, you would instead perform a rolling update to avoid downtime of the
DNS service. The outcome for this simple guide is effectively the same though.

::

    $ kubectl --namespace kube-system delete pods -l k8s-app=kube-dns
    pod "kube-dns-268032401-t57r2" deleted

Running ``kubectl get pods`` will show you that Kubernetes started a new set of
``kube-dns`` pods while at the same time terminating the old pods:

::

    $ kubectl --namespace kube-system get pods
    NAME                          READY     STATUS        RESTARTS   AGE
    cilium-5074s                  1/1       Running       0          58m
    cilium-consul-plxdm           1/1       Running       0          58m
    kube-addon-manager-minikube   1/1       Running       0          59m
    kube-dns-268032401-j0vml      3/3       Running       0          9s
    kube-dns-268032401-t57r2      3/3       Terminating   0          57m


Step 3: Deploy the demo pods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Now that we have Cilium deployed and ``kube-dns`` operating correctly we can
deploy an actual application. The file ``demo.yaml`` contains two Kubernetes
resources:

- A Deployment_ "backend" which will create a backend pod with two replicas. The
  backend pod provides a REST API to frontends.
- A Service_ "backend" which exposes all pods of the deployment via a
  *ClusterIP* to make them highly available. ``kube-dns`` will automatically
  resolve the service name *backend* to this *ClusterIP*.
- A Deployment_ "frontend" which will create a pod that we can execute from.

::

    $ kubectl create -f 
    service "backend" created
    deployment "backend" created
    deployment "frontend" created

Just like when we deployed Cilium as a DaemonSet_, Kubernetes will deploy the
pods and service  in the background.  Running ``kubectl get svc,pods`` will
inform you about the progress of the operation. Each pod will go through
several states until it reaches ``Running`` at which point the pod is ready.

::

    $ kubectl get svc,pod
    NAME             CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
    svc/backend      10.0.0.21    <none>        80/TCP    13s
    svc/kubernetes   10.0.0.1     <none>        443/TCP   34m

    NAME                          READY     STATUS              RESTARTS   AGE
    po/backend-1758924707-9vg1n   1/1       Running             0          13s
    po/backend-1758924707-k32p7   1/1       Running             0          13s
    po/frontend-504426975-gcv8g   0/1       ContainerCreating   0          13s

Step 4: Apply an L3/L4 Policy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using Cilium, endpoint IP addresses are irrelevant when defining security
policies.  Instead, you can use the labels assigned to the VM to define
security policies, which are automatically applied to any container with that
label, no matter where or when it is run within a container cluster.

Kubernetes requires to enable isolation per namespace. Therefore, we enable
it in the ``default`` namespace where our demo app is running.

TODO: This step is not functional yet PR552. Enforcment is automatically
enabled when the first policy is loaded.

::

    $ kubectl patch ns default -p '{"spec": {"networkPolicy": {"ingress": {"isolation": "DefaultDeny"}}}}'
    "default" patched

We'll start with a simple example where we allow connectivity between the
frontend and the backend. Other pods should not be able to reach the backend.
Additionally, we want backend to be reachable only on port 80, but no other
ports.  This is a simple policy that filters only on IP protocol (network layer
3) and TCP protocol (network layer 4), so it is often referred to as an L3/L4
network security policy.

Cilium performs stateful *connection tracking*, meaning that if policy allows
the frontend to reach backend, it will automatically allow all required reply
packets that are part of backend replying to frontend within the context of the
same TCP/UDP connection.

We can achieve that with the following Kubernetes NetworkPolicy:

::

    kind: NetworkPolicy
    apiVersion: extensions/v1beta1
    metadata:
      name: access-backend
    spec:
      podSelector:
        matchLabels:
          role: backend
      ingress:
      - from:
        - podSelector:
            matchLabels:
              role: frontend
        ports:
        - port: 80
          protocol: TCP

Save this YAML to a file named ``l3_l4_policy.yaml`` in your VM, and apply the
policy by using ``kubectl create -f``:

::

  $ kubectl create -f l3_l4_policy.yaml

Step 5: Test L3/L4 Policy
^^^^^^^^^^^^^^^^^^^^^^^^^

We can now verify the network policy that was imported.
You can now launch additional containers represent other services attempting to
access backend. Any new container with label `app=demo, role=frontend` will be
allowed to access the backend on port 80, otherwise the network request will be
dropped.

To test this out, we'll make an HTTP request to backend from a container
with the labels `app=demo, role=frontend`:

TODO: PR552 is blocking kube-dns to be allowed if isolation is not enabled
      in kube-system namespace

::

    POD=$(kubectl get pods -l role=frontend -o jsonpath='{.items[0].metadata.name}')
    kubectl exec $POD -- curl -s backend
    <html><body><h1>It works!</h1></body></html>

Step 5:  Apply and Test an L7 Policy using Annotations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO

Getting Started using Vagrant
-----------------------------

The tutorial leverages Vagrant, and as such should run on any operating system
supported by Vagrant, including Linux, MacOS X, and Windows. The VM running
Docker + Cilium requires about 3 GB of RAM, so if your laptop has limited
resources, you may want to close other memory intensive applications.

The vagrant box is currently available for the following hypervisors. Please
contact us on `slack <https://cilium.herokuapp.com>`_ to request building for
additional hypervisors.
 * VirtualBox
 * libvirt

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_ .  With Cilium contributors
across the globe, there is almost always someone available to help.

Step 0: Install Vagrant
^^^^^^^^^^^^^^^^^^^^^^^

.. note::

   You need to run Vagrant version 1.8.3 or later or you will run into issues
   booting the Ubuntu 16.10 base image. You can verify by running ``vagrant --version``.

If you don't already have Vagrant installed, follow the
`Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_
or see `Download Vagrant <https://www.vagrantup.com/downloads.html>`_ for newer versions.


Step 1: Download the Cilium Source Code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Download the latest Cilium `source code <https://github.com/cilium/cilium/archive/master.zip>`_
and unzip the files.

Alternatively, if you are a developer, feel free to use Git to clone the
repository:

::

    $ git clone https://github.com/cilium/cilium

Step 2: Starting the Docker + Cilium VM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Open a terminal and navigate into the top of the cilium source directory.

Then navigate into `examples/getting-started` and run `vagrant up`:

::

    $ cd examples/getting-started
    $ vagrant up

The script usually takes a few minutes depending on the speed of your internet
connection. Vagrant will set up a VM, install the Docker container runtime and
run Cilium with the help of Docker compose. When the script completes successfully,
it will print:

::

    ==> cilium-1: Creating cilium-kvstore
    ==> cilium-1: Creating cilium
    ==> cilium-1: Creating cilium-docker-plugin
    $

If the script exits with an error message, do not attempt to proceed with the
tutorial, as later steps will not work properly.   Instead, contact us on the
`Cilium Slack channel <https://cilium.herokuapp.com>`_ .

Step 3: Accessing the VM
^^^^^^^^^^^^^^^^^^^^^^^^

After the script has successfully completed, you can log into the VM using
``vagrant ssh``:

::

    $ vagrant ssh


All commands for the rest of the tutorial below should be run from inside this
Vagrant VM.  If you end up disconnecting from this VM, you can always reconnect
in a new terminal window just by running ``vagrant ssh`` again from the Cilium
directory.


Step 4: Confirm that Cilium is Running
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cilium integrates with local container runtimes, which in the case of this demo
means Docker. With Docker, native networking is handled via a component called
libnetwork. In order to steer Docker to request networking of a container from
Cilium, a container must be started with a network of driver type "cilium".

With Cilium, all containers are connected to a single logical network, with
isolation added not based on IP addresses but based on container labels (as we
will do in the steps below). So with Docker, we simply create a single network
named 'cilium-net' for all containers:

::

    $ docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium-net


Step 6: Start an Example Service with Docker
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this tutorial, we'll use a container running a simple HTTP server to
represent a microservice which we will refer to as *Service1*.  As a result, we
will start this container with the label "id.service1", so we can create Cilium
security policies for that service.

Use the following command to start the *Service1* container connected to the
Docker network managed by Cilium:

::

    $ docker run -d --name service1-instance1 --net cilium-net -l "id.service1" cilium/demo-httpd
    e5723edaa2a1307e7aa7e71b4087882de0250973331bc74a37f6f80667bc5856


This has launched a container running an HTTP server which Cilium is now
managing as an `endpoint`. A Cilium endpoint is one or more application
containers which can be addressed by an individual IP address.


Step 7: Apply an L3/L4 Policy With Cilium
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using Cilium, endpoint IP addresses are irrelevant when defining security
policies.  Instead, you can use the labels assigned to the VM to define
security policies, which are automatically applied to any container with that
label, no matter where or when it is run within a container cluster.

We'll start with an overly simple example where we create two additional
services, *Service2* and *Service3*, and we want Service2 containers to be able
to reach *Service1* containers, but *Service3* containers should not be allowed
to reach *Service1* containers.  Additionally, we only want to allow *Service1*
to be reachable on port 80, but no other ports.  This is a simple policy that
filters only on IP address (network layer 3) and TCP port (network layer 4), so
it is often referred to as an L3/L4 network security policy.

Cilium performs stateful ''connection tracking'', meaning that if policy allows
the *Service2* to contact *Service3*, it will automatically allow return
packets that are part of *Service1* replying to *Service2* within the context
of the same TCP/UDP connection.

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

Save this JSON to a file named l3_l4_policy.json in your VM, and apply the
policy by running:

::

  $ cilium policy import l3_l4_policy.json


Step 8: Test L3/L4 Policy
^^^^^^^^^^^^^^^^^^^^^^^^^


You can now launch additional containers represent other services attempting to
access *Service1*. Any new container with label "id.service2" will be allowed
to access *Service1* on port 80, otherwise the network request will be dropped.

To test this out, we'll make an HTTP request to *Service1* from a container
with the label "id.service2" :

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" --cap-add NET_ADMIN cilium/demo-client ping service1-instance1
    PING service1-instance1 (10.11.250.189): 56 data bytes
    64 bytes from 10.11.250.189: seq=4 ttl=64 time=0.100 ms
    64 bytes from 10.11.250.189: seq=5 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=6 ttl=64 time=0.070 ms
    64 bytes from 10.11.250.189: seq=7 ttl=64 time=0.084 ms
    64 bytes from 10.11.250.189: seq=8 ttl=64 time=0.107 ms
    64 bytes from 10.11.250.189: seq=9 ttl=64 time=0.103 ms

We can see that this request was successful, as we get a valid ping responses.

Now let's run the same ping request to *Service1* from a container that has
label "id.service3":

::

    $ docker run --rm -ti --net cilium-net -l "id.service3" --cap-add NET_ADMIN cilium/demo-client ping service1-instance1

You will see no ping replies, as all requests are dropped by the Cilium
security policy.

So with this we see Cilium's ability to segment containers based purely on a
container-level identity label.  This means that the end user can apply
security policies without knowing anything about the IP address of the
container or requiring some complex mechanism to ensure that containers of a
particular service are assigned an IP address in a particular range.


Step 9:  Apply and Test an L7 Policy with Cilium
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the simple scenario above, it was sufficient to either give *Service2* /
*Service3* full access to *Service1's* API or no access at all.   But to
provide the strongest security (i.e., enforce least-privilege isolation)
between microservices, each service that calls *Service1's* API should be
limited to making only the set of HTTP requests it requires for legitimate
operation.

For example, consider a scenario where *Service1* has two API calls:
 * GET /public
 * GET /private

Continuing with the example from above, if *Service2* requires access only to
the GET /public API call, the L3/L4 policy along has no visibility into the
HTTP requests, and therefore would allow any HTTP request from *Service2*
(since all HTTP is over port 80).

To see this, run:

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/public'
    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/private'
    { 'val': 'this is private' }

Cilium is capable of enforcing HTTP-layer (i.e., L7) policies to limit what
URLs *Service2* is allowed to reach.  Here is an example policy file that
extends our original policy by limiting *Service2* to making only a GET /public
API call, but disallowing all other calls (including GET /private).

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
                "l7-parser": "http",
                "l7-rules": [
                    { "expr": "Method(\"GET\") && Path(\"/public\")" }
                ]
            }]
        }]
    }]
  }

Create a file with this contents and name it l7_aware_policy.json. Then
import this policy to Cilium by running:

::

  $ cilium policy import l7_aware_policy.json

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/public'
    { 'val': 'this is public' }

and

::

    $ docker run --rm -ti --net cilium-net -l "id.service2" cilium/demo-client curl -si 'http://service1-instance1/private'
    Access denied

As you can see, with Cilium L7 security policies, we are able to permit
*Service2* to access only the required API resources on *Service1*, thereby
implementing a "least privilege" security approach for communication between
microservices.

We hope you enjoyed the tutorial.  Feel free to play more with the setup, read
the rest of the documentation, and feel free to reach out to us on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_ with any questions!


Step 10: Clean-Up
^^^^^^^^^^^^^^^^^

When you are done with the setup and want to tear-down the Cilium + Docker VM,
and destroy all local state (e.g., the VM disk image), open a terminal, navigate to
the cilium directory and run:

::

    $ vagrant destroy cilium-1

You can always re-create the VM using the steps described above.

If instead you just want to shut down the VM but may use it later,
``vagrant halt cilium-1`` will work, and you can start it again later
using the contrib/vagrant/start.sh script.

.. _DaemonSet: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/
.. _Deployment: https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
.. _Service: https://kubernetes.io/docs/concepts/services-networking/service/
