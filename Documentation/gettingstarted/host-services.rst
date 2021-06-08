.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _host-services:

***********************
Host-Reachable Services
***********************

This guide explains how to configure Cilium to enable services to be reached
from the host namespace in addition to pod namespaces.

.. note::

   Host-reachable services for TCP and UDP requires a v4.19.57, v5.1.16, v5.2.0
   or more recent Linux kernel. Note that v5.0.y kernels do not have the fix
   required to run host-reachable services with UDP since at this point in time
   the v5.0.y stable kernel is end-of-life (EOL) and not maintained anymore. For
   only enabling TCP-based host-reachable services a v4.17.0 or newer kernel
   is required. The most optimal kernel with the full feature set is v5.8.

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set hostServices.enabled=true

If you can't run 4.19.57 but have 4.17.0 available you can restrict protocol
support to TCP only:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set hostServices.enabled=true \\
     --set hostServices.protocols=tcp

Host-reachable services act transparent to Cilium's lower layer datapath
in that upon connect system call (TCP, connected UDP) or sendmsg as well
as recvmsg (UDP) the destination IP is checked for an existing service IP
and one of the service backends is selected as a target, meaning, while
the application is assuming its connection to the service address, the
corresponding kernel's socket is actually connected to the backend address
and therefore no additional lower layer NAT is required.

Verify that it has come up correctly:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

Limitations
###########

    * The kernel eBPF cgroup hooks operate at connect(2), sendmsg(2) and
      recvmsg(2) system call layers for connecting the application to one
      of the service backends. In the v5.8 Linux kernel, a getpeername(2)
      hook for eBPF has been added in order to also reverse translate the
      connected sock addresses for application's getpeername(2) calls in
      Cilium. For kernels older than v5.8 such reverse translation is not
      taking place for this system call. For the vast majority of applications
      not having this translation at getpeername(2) does not cause any
      issues. There is one known case for libceph where its monitor might
      return an error since expected peer address mismatches.
