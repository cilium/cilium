.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
      http://docs.cilium.io

Welcome to Cilium's documentation!
==================================

The documentation is divided into the following sections:

* :ref:`gs_guide`: Provides a simple tutorial for running a small Cilium
  setup on your laptop.  Intended as an easy way to get your hands dirty
  applying Cilium security policies between containers.

* :ref:`arch_guide`: Describes the components of the Cilium architecture,
  and the different models for deploying Cilium.  Provides the high-level
  understanding required to run a full Cilium deployment and understand its
  behavior.

* :ref:`install_guide` :  Details instructions for installing, configuring, and
  troubleshooting Cilium in different deployment modes.

* :ref:`policy_guide` : Detailed walkthrough of the policy language structure
  and the supported formats.

* :ref:`metrics` : Instructions for configuring metrics collection from Cilium.

* :ref:`admin_guide` : Describes how to troubleshoot Cilium in different
  deployment modes.

* :ref:`bpf_guide` : Provides a technical deep dive of BPF and XDP technology,
  primarily focused at developers.

* :ref:`api_ref` : Details the Cilium agent API for interacting with a local
  Cilium instance.

* :ref:`dev_guide` : Gives background to those looking to develop and contribute
  modifications to the Cilium code or documentation.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   intro
   gettingstarted/index
   concepts
   gettinghelp

.. toctree::
   :maxdepth: 2
   :caption: Integrations

   kubernetes/index
   istio/index
   docker/index
   mesos/index

.. toctree::
   :maxdepth: 2
   :caption: Administration

   install/system_requirements
   install/guides/index
   install/upgrade

.. toctree::
   :maxdepth: 2
   :caption: Configuration
   :glob:

   policy/index
   configuration/*
   troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: For Developers

   contributing
   bpf
   api

.. toctree::
   :maxdepth: 2
   :caption: Reference

   cheatsheet
   cmdref/index
   kvstore
   further_reading
   glossary
