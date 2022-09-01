.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _rancher_desktop_install:

**********************************
Installation Using Rancher Desktop
**********************************

This guide walks you through installation of Cilium on `Rancher Desktop <https://rancherdesktop.io>`_,
an open-source desktop application for Mac, Windows and Linux.

Configure Rancher Desktop
=========================

.. include:: rancher-desktop-configure.rst

Install Cilium
==============

.. include:: cli-download.rst

Install Cilium by running:

.. code-block:: shell-session

    cilium install

Validate the Installation
=========================

.. include:: cli-status.rst
.. include:: cli-connectivity-test.rst

.. include:: next-steps.rst

