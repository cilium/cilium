.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kata-gce:

******************************
Kata with Cilium on Google GCE
******************************

Kata Containers is an open source project that provides a secure container
runtime with lightweight virtual machines that feel and perform like containers,
but provide stronger workload isolation using hardware virtualization technology
as a second layer of defense.
Similar to the OCI runtime ``runc`` provided by Docker, Cilium can be used with
Kata Containers, providing a higher degree of security at the network layer and
at the compute layer with Kata.
This guide provides a walkthrough of installing Kata with Cilium on GCE.
Kata Containers on Google Compute Engine (GCE) makes use of nested virtualization.
At the time of this writing, nested virtualization support was not yet available
on GKE.

GCE Requirements
================

1. Install the Google Cloud SDK (``gcloud``) see `Installing Google Cloud SDK <https://cloud.google.com/sdk/install>`_
   Verify your gcloud installation and configuration:

.. code:: bash

    gcloud info || { echo "ERROR: no Google Cloud SDK"; exit 1; }

2. Create a project or use an existing one

.. code:: bash

   export GCE_PROJECT=kata-with-cilium
   gcloud projects create $GCE_PROJECT


Create an image on GCE with Nested Virtualization support
=========================================================

As mentioned before, Kata Containers on Google Compute Engine (GCE) makes use of
nested virtualization. As a prerequisite you need to create an image with
nested virtualization enabled in your currently active GCE project.

1. Choose a base image

Officially supported images are automatically discoverable with:

.. code:: bash

  gcloud compute images list
  NAME                                                  PROJECT            FAMILY                            DEPRECATED  STATUS
  centos-6-v20190423                                    centos-cloud       centos-6                                      READY
  centos-7-v20190423                                    centos-cloud       centos-7                                      READY
  coreos-alpha-2121-0-0-v20190423                       coreos-cloud       coreos-alpha                                  READY
  cos-69-10895-211-0                                    cos-cloud          cos-69-lts                                    READY
  ubuntu-1604-xenial-v20180522                          ubuntu-os-cloud    ubuntu-1604-lts                               READY
  ubuntu-1804-bionic-v20180522                          ubuntu-os-cloud    ubuntu-1804-lts                               READY

Select an image based on project and family rather than by name. This ensures
any scripts or other automation always works with a non-deprecated image,
including security updates, updates to GCE-specific scripts, etc.

2. Create the image with nested virtualization support

.. code:: bash

  SOURCE_IMAGE_PROJECT=ubuntu-os-cloud
  SOURCE_IMAGE_FAMILY=ubuntu-1804-lts
  IMAGE_NAME=${SOURCE_IMAGE_FAMILY}-nested

  gcloud compute images create \
      --source-image-project $SOURCE_IMAGE_PROJECT \
      --source-image-family $SOURCE_IMAGE_FAMILY \
      --licenses=https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx \
      $IMAGE_NAME

If successful, gcloud reports that the image was created.

3. Verify VMX is enabled

Verify that a virtual machine created with the previous image has VMX enabled.

.. code:: bash

  gcloud compute instances create \
    --image $IMAGE_NAME \
    --machine-type n1-standard-2 \
    --min-cpu-platform "Intel Broadwell" \
    kata-testing

  gcloud compute ssh kata-testing
  # While ssh'd into the VM:
  $ [ -z "$(lscpu|grep GenuineIntel)" ] && { echo "ERROR: Need an Intel CPU"; exit 1; }

Setup Kubernetes with CRI
=========================

Kata Containers runtime is an OCI compatible runtime and cannot directly interact
with the CRI API level. For this reason we rely on a CRI implementation to translate
CRI into OCI. There are two supported ways called CRI-O and CRI-containerd.
It is up to you to choose the one that you want, but you have to pick one.

If you select CRI-O, follow the "CRI-O Tutorial" instructions
`here <https://github.com/cri-o/cri-o/blob/master/tutorial.md/>`__ to properly install it.
If you select containerd with cri plugin, follow the "Getting Started for Developers"
instructions `here <https://github.com/containerd/cri#getting-started-for-developers>`__ to properly install it.

Setup your Kubernetes environment and make sure the following requirements are met:

* Kubernetes >= 1.12
* Linux kernel >= 4.9
* Kubernetes in CNI mode
* Running kube-dns/coredns (When using the etcd-operator installation method)
* Mounted BPF filesystem mounted on all worker nodes
* Enable PodCIDR allocation (``--allocate-node-cidrs``) in the ``kube-controller-manager`` (recommended)

Refer to the section :ref:`k8s_requirements` for detailed instruction on how to
prepare your Kubernetes environment.

.. note::
   Minimum version of kubernetes 1.12 is required to use the RuntimeClass Feature
   for Kata Container runtime described below. It is possible to use kubernetes<=1.10
   with Kata, but that requires for a slightly different setup that has been
   deprecated.

Kubernetes talks with CRI implementations through a container-runtime-endpoint,
also called CRI socket. This socket path is different depending on which CRI
implementation you chose, and the kubelet service has to be updated accordingly.

Configure Kubernetes for CRI-O
------------------------------

Add ``/etc/systemd/system/kubelet.service.d/0-crio.conf``

::

  [Service]
  Environment="KUBELET_EXTRA_ARGS=--container-runtime=remote --runtime-request-timeout=15m --container-runtime-endpoint=unix:///var/run/crio/crio.sock"

Configure for Kubernetes for containerd
---------------------------------------

Add ``/etc/systemd/system/kubelet.service.d/0-cri-containerd.conf``

::

  [Service]
  Environment="KUBELET_EXTRA_ARGS=--container-runtime=remote --runtime-request-timeout=15m --container-runtime-endpoint=unix:///run/containerd/containerd.sock"

After you update your kubelet service based on the CRI implementation you are
using, reload and restart kubelet.

Deploy Cilium
=============

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.containerRuntime.integration=crio \
     > cilium.yaml
   kubectl create -f cilium.yaml

.. note::

   If you are using ``containerd``, set ``global.containerRuntime.integration=containerd``.

Validate cilium
===============

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n kube-system get pods --watch
    NAME                                    READY   STATUS              RESTARTS   AGE
    cilium-cvp8q                            0/1     Init:0/1            0          53s
    cilium-operator-788c55554-gkpbf         0/1     ContainerCreating   0          54s
    cilium-tdzcx                            0/1     Init:0/1            0          53s
    coredns-77b578f78d-km6r4                1/1     Running             0          11m
    coredns-77b578f78d-qr6gq                1/1     Running             0          11m
    kube-proxy-l47rx                        1/1     Running             0          6m28s
    kube-proxy-zj6v5                        1/1     Running             0          6m28s

It may take a couple of minutes for the etcd-operator to bring up the necessary
number of etcd pods to achieve quorum. Once it reaches quorum, all components
should be healthy and ready:

.. parsed-literal::

   kubectl -n=kube-system get pods
   NAME                                    READY   STATUS    RESTARTS   AGE
   cilium-cvp8q                            1/1     Running   0          42s
   cilium-operator-788c55554-gkpbf         1/1     Running   2          43s
   cilium-tdzcx                            1/1     Running   0          42s
   coredns-77b578f78d-2khwp                1/1     Running   0          13s
   coredns-77b578f78d-bs6rp                1/1     Running   0          13s
   kube-proxy-l47rx                        1/1     Running   0          6m
   kube-proxy-zj6v5                        1/1     Running   0          6m

For troubleshooting any issues, please refer to :ref:`k8s_install_etcd_operator`

Install Kata on a running Kubernetes Cluster
============================================

Kubernetes configured with CRI runtimes by default uses ``runc`` runtime for running a
workload. You will need to configure Kubernetes to be able to use an alternate runtime.

`RuntimeClass <https://kubernetes.io/docs/concepts/containers/runtime-class/>`_
is a Kubernetes feature first introduced in Kubernetes 1.12 as alpha. It is the
feature for selecting the container runtime configuration to use
to run a pod’s containers.
To use Kata-Containers, ensure the RuntimeClass feature gate is enabled for k8s < 1.13.
It is enabled by default on k8s 1.14.
See `Feature Gates <https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/>`_
for an explanation of enabling feature gates.

To install Kata Containers and configure CRI to use Kata as a one step process,
you will use `kata-deploy <https://github.com/kata-containers/packaging/tree/master/kata-deploy>`_
tool as shown below.

1) Install Kata on a running k8s cluster

.. code:: bash

  kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/kata-rbac.yaml
  kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/kata-deploy.yaml

This will install all the required Kata binaries under ``/opt/kata`` and configure
CRI implementation with the RuntimeClass handlers for the Kata runtime binaries.
Kata Containers can leverage Qemu and Firecracker hypervisor for running
the lightweight VM. ``kata-fc`` binary runs a Firecracker isolated Kata Container while
``kata-qemu`` runs a Qemu isolated Kata Container.

2) Create the RuntimeClass resource for Kata-containers

To add a RuntimeClass for Qemu isolated Kata-Containers:

.. tabs::
  .. group-tab:: K8s 1.14

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.14/kata-qemu-runtimeClass.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.13/kata-qemu-runtimeClass.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.13/kata-qemu-runtimeClass.yaml

To add a RuntimeClass for Firecracker isolated Kata-Containers:

.. tabs::
  .. group-tab:: K8s 1.14

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.14/kata-fc-runtimeClass.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.13/kata-fc-runtimeClass.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/k8s-1.13/kata-fc-runtimeClass.yaml

Run Kata Containers with Cilium CNI
===================================

Now that Kata is installed on the k8s cluster, you can run an untrusted workload
with Kata Containers with Cilium as the CNI.

The following YAML snippet shows how to specify a workload should use Kata with QEMU:

::

  spec:
    template:
      spec:
        runtimeClassName: kata-qemu

The following YAML snippet shows how to specify a workload should use Kata with Firecracker:

::

  spec:
    template:
      spec:
        runtimeClassName: kata-fc

To run an example pod with kata-qemu:

.. code:: bash

  kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/examples/test-deploy-kata-qemu.yaml

To run an example with kata-fc:

.. code:: bash

  kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/4bb97ef14a4ba8170b9d501b3e567037eb0f9a41/kata-deploy/examples/test-deploy-kata-fc.yaml
