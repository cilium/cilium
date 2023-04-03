.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _testing-documentation:

Documentation Testing
=====================

First, start a local document server that automatically refreshes when you save files for
real-time preview. It relies on the ``cilium/docs-builder`` Docker container.

Set up your development environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To run Cilium's documentation locally, you need to install `docker engine <https://docs.docker.com/engine/install/>`_ and also the ``make`` package.
To verify that ``make`` and ``docker`` is installed, run the command ``make --version`` and ``docker --version`` in your terminal.

.. code-block:: shell-session

    $ docker --version
    Docker version 20.10.22, build 3a2c30b
    $ make --version
    GNU Make 4.2.1

For Windows
~~~~~~~~~~~

.. Note::
    The preferred method is to upgrade to Windows 10 version 1903 Build 18362 or higher, you can upgrade to Windows Subsystem for Linux ``WSL2`` and run ``make`` in Linux.

#. Verify you have access to the ``make`` command in your ``WSL2`` terminal.
#. Download and install docker desktop.
#. Set up docker to use `WSL2 <https://docs.docker.com/desktop/windows/wsl/>`_ as backend.
#. Start docker desktop.

Preview Documentation Locally
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Navigate to the root of the folder where you cloned the project.

.. code-block:: shell-session
    
    $ cd "${GOPATH}/src/github.com/cilium/cilium"

Run the code below in your terminal:

.. code-block:: shell-session

    $ make render-docs


This will build a docker image and start a docker container. Preview the documentation at http://localhost:9081/ as you make changes. After making changes to
Cilium documentation you should check that you did not introduce any new warnings or errors, and also
check that your changes look as you intended one last time before opening a pull request. To do this
you can build the docs:

.. code-block:: shell-session

    $ make test-docs

.. note::

   By default, ``render-docs`` generates a preview with instructions to install
   Cilium from the latest version on GitHub (i.e. from the HEAD of the main branch that has
   not been released) regardless of which Cilium branch you are in. You can target a specific
   branch by specifying ``READTHEDOCS_VERSION`` environment variable:

   .. code-block:: shell-session

      READTHEDOCS_VERSION=v1.7 make render-docs

    
Submit Local Changes on GitHub (Pull Request)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
See the :ref:`submit a pull request <submit_pr>` section of the contributing guide.
