.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Welcome to Cilium's documentation!
==================================

The documentation is divided into the following sections:

* :ref:`k8s_install_quick`: Provides a simple tutorial for running a small Cilium
  setup on your laptop.  Intended as an easy way to get your hands dirty
  applying Cilium security policies between containers.

* :ref:`getting_started` :  Details instructions for installing, configuring, and
  troubleshooting Cilium in different deployment modes.

* :ref:`network_policy` : Detailed walkthrough of the policy language structure
  and the supported formats.

* :ref:`metrics` : Instructions for configuring metrics collection from Cilium.

* :ref:`admin_guide` : Describes how to troubleshoot Cilium in different
  deployment modes.

* :ref:`bpf_guide` : Provides a technical deep dive of eBPF and XDP technology,
  primarily focused at developers.

* :ref:`api_ref` : Details the Cilium agent API for interacting with a local
  Cilium instance.

* :ref:`dev_guide` : Gives background to those looking to develop and contribute
  modifications to the Cilium code or documentation.

* :ref:`security_root` : Provides a one-page resource of best practices for securing Cilium.

A `hands-on tutorial <https://cilium.io/enterprise/#trainings>`_
in a live environment is also available for users looking for a way to quickly
get started and experiment with Cilium.

.. toctree::
   :maxdepth: 2
   :caption: Overview

   overview/intro
   overview/component-overview

.. _getting_started:

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   gettingstarted/k8s-install-default
   gettingstarted/hubble_intro
   gettingstarted/hubble_setup
   gettingstarted/hubble-configuration
   gettingstarted/hubble
   gettingstarted/hubble_cli.rst
   gettingstarted/demo
   gettingstarted/terminology
   gettingstarted/gettinghelp

.. toctree::
   :maxdepth: 2
   :caption: Advanced Installation

   installation/taints
   installation/k8s-install-helm
   installation/k8s-install-migration
   installation/k8s-toc
   installation/external-toc

.. toctree::
   :maxdepth: 2
   :caption: Networking

   network/concepts/index
   network/kubernetes/index
   network/bgp-toc
   network/ebpf/index
   network/clustermesh/index
   network/external-toc
   network/egress-gateway-toc
   network/servicemesh/index
   network/vtep
   network/l2-announcements
   network/node-ipam
   network/pod-mac-address
   network/multicast

.. toctree::
   :maxdepth: 2
   :caption: Security

   security/index
   security/network/index
   security/policy/index
   security/restrict-pod-access
   security/threat-model

.. toctree::
   :maxdepth: 2
   :caption: Observability

   observability/grafana
   observability/metrics
   observability/visibility
   observability/hubble-exporter

.. toctree::
   :maxdepth: 2
   :caption: Operations

   operations/system_requirements
   operations/upgrade
   configuration/index
   operations/performance/index
   operations/troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: Community

   community/governance
   community/community
   community/roadmap

.. toctree::
   :maxdepth: 2
   :caption: Contributor Guide

   contributing/development/index
   contributing/release/index
   contributing/testing/index
   contributing/docs/index
   api
   grpcapi
   internals/index

.. toctree::
   :maxdepth: 2
   :caption: Reference

   cheatsheet
   cmdref/index
   helm-reference
   kvstore
   further_reading
   glossary

.. toctree::
   :maxdepth: 2
   :caption: BPF and XDP Reference Guide

   bpf/index
