.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _host-services:

******************************
Host-Reachable Services (beta)
******************************

This guide explains how to configure Cilium to enable services to be
reached from the host namespace.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

.. note::

   Host-reachable services for TCP and UDP requires a v4.19.57, v5.1.16, v5.2.0
   or more recent Linux kernel. Note that v5.0.y kernels do not have the fix
   required to run host-reachable services with UDP since at this point in time
   the v5.0.y stable kernel is end-of-life (EOL) and not maintained anymore. For
   only enabling TCP-based host-reachable services a v4.17.0 or newer kernel
   is required.

.. include:: k8s-install-download-release.rst

Generate the required YAML file and deploy it:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.hostServices.enabled=true \
     > cilium.yaml

If you can't run 4.19.57 but have 4.17.0 available you can restrict protocol
support to TCP only:

.. code:: bash

   helm template cilium \
     --namespace kube-system \
     --set global.hostServices.enabled=true \
     --set global.hostServices.protocols=tcp \
     > cilium.yaml

Host-reachable services act transparent to Cilium's lower layer datapath
in that upon connect system call (TCP, connected UDP) or sendmsg as well
as recvmsg (UDP) the destination IP is checked for an existing service IP
and one of the service backends is selected as a target, meaning, while
the application is assuming its connection to the service address, the
corresponding kernel's socket is actually connected to the backend address
and therefore no additional lower layer NAT is required.

Deploy Cilium:

.. code:: bash

    kubectl create -f cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

Limitations
###########

    * The kernel BPF cgroup hooks operate at connect(2), sendmsg(2) and
      recvmsg(2) system call layers for connecting the application to one
      of the service backends. Currently getpeername(2) does not yet have
      a BPF hook for rewriting sock addresses before copying them into
      user space in which case the application will see the backend address
      instead of the service address. This limitation will be resolved in
      future kernels.
