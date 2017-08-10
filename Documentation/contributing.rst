.. _dev_guide:

Developer / Contributor Guide
=============================

We're happy you're interested in contributing to the Cilium project.

This guide will help you make sure you have an environment capable of testing
changes to the Cilium source code, and that you understand the workflow of getting
these changes reviewed and merged upstream.

Setting up a development environment
------------------------------------

Developer requirements
~~~~~~~~~~~~~~~~~~~~~~

You need to have the following tools available in order to effectively
contribute to Cilium:

+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID   | Download Command                                           |
+==================================================================================+=======================+============================================================+
| git                                                                              | latest                | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go <https://golang.org/dl/>`_                                                   | 1.8.3                 | N/A (OS-specific)                                          |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go-swagger <https://github.com/go-swagger/go-swagger/tree/master/cmd/swagger>`_ | `fbc64c26`            | ``go get -u github.com/go-swagger/go-swagger/cmd/swagger`` |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+
| `go-bindata <https://github.com/jteeuwen/go-bindata>`_                           | `a0ff2567cfb`         | ``go get -u github.com/jteeuwen/go-bindata/...``           |
+----------------------------------------------------------------------------------+-----------------------+------------------------------------------------------------+

To run Cilium locally on VMs, you need:

+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| Dependency                                                                       | Version / Commit ID   | Download Command                                                               |
+==================================================================================+=======================+================================================================================+
| `Vagrant <https://www.vagrantup.com/downloads.html>`_                            | >= 1.8.3              | `Vagrant Install Instructions <https://www.vagrantup.com/docs/installation/>`_ |
+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+
| `VirtualBox <https://www.virtualbox.org/wiki/Downloads>`_ (if not using libvirt) | >= 5.1.22             | N/A (OS-specific)                                                              |
+----------------------------------------------------------------------------------+-----------------------+--------------------------------------------------------------------------------+

Finally, in order to build the documentation, you should have Sphinx installed:

::

    $ sudo pip install sphinx
  
You should start with the :ref:`gs_guide`, which walks you through the
set-up, such as installing Vagrant, getting the Cilium sources, and
going through some Cilium basics.

  
Vagrant Setup
~~~~~~~~~~~~~

While the the :ref:`gs_guide` uses a Vagrantfile tuned for the basic
walk through, the setup for the Vagrantfile in the root of the Cilium
tree depends on a number of environment variables and network setup
that are managed via ``contrib/vagrant/start.sh``.

Using the provided Vagrantfile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To bring up a Vagrant VM  with Cilium
plus dependencies installed, run:

::

    $ contrib/vagrant/start.sh

This will create and run a vagrant VM based on the base box
``cilium/ubuntu-16.10``. The box is currently available for the
following providers:

* libvirt
* virtualbox

Options
^^^^^^^

The following environment variables can be set to customize the VMs
brought up by vagrant:

* ``NWORKERS=n``: Number of child nodes you want to start with the master,
  default 0.
* ``RELOAD=1``: Issue a ``vagrant reload`` instead of ``vagrant up``
* ``NFS=1``: Use NFS for vagrant shared directories instead of rsync
* ``K8S=1``: Build & install kubernetes on the nodes
* ``IPV4=1``: Run Cilium with IPv4 enabled
* VAGRANT\_DEFAULT\_PROVIDER={virtualbox \| libvirt \| ...}

If you want to start the VM with cilium enabled with IPv4, with
kubernetes installed and plus a worker, run:

::

	$ IPV4=1 K8S=1 NWORKERS=1 contrib/vagrant/start.sh

If you have any issue with the provided vagrant box
``cilium/ubuntu-16.10`` or need a different box format, you may
build the box yourself using the `packer scripts <https://github.com/cilium/packer-ubuntu-16.10>`_

Manual Installation
^^^^^^^^^^^^^^^^^^^

Alternatively you can import the vagrant box ``cilium/ubuntu-16.10``
directly and manually install Cilium:

::

        $ vagrant init cilium/ubuntu-16.10
        $ vagrant up
        $ vagrant ssh [...]
        $ cd go/src/github.com/cilium/cilium/
        $ make
        $ sudo make install
        $ sudo cp contrib/upstart/* /etc/init/
        $ sudo usermod -a -G cilium vagrant
        $ sudo service cilium restart

Notes
^^^^^

Your Cilium tree is mapped to the VM so that you do not need to keep
copying files between your host and the VM.  The default sync method
is rsync, which only syncs when the VM is brought up, or when manually
triggered (``vagrant rsync`` command in the Cilium tree).  You can
also use NFS to access your Cilium tree from the VM by setting the
environment variable ``NFS`` (mentioned above) before running the startup script
(``export NFS=1``).  Note that your host firewall have the NFS UDP
ports open, the startup script will give the address and port details
for this.

.. note::

   OSX file system is by default case insensitive, which can confuse
   git.  At the writing of this Cilium repo has no file names that
   would be considered referring to the same file on a case
   insensitive file system.  Regardless, it may be useful to create a
   disk image with a case sensitive file system for holding your git
   repos.

.. note::

   VirtualBox for OSX currently (version 5.1.22) always reports
   host-only networks' prefix length as 64.  Cilium needs this prefix
   to be 16, and the startup script will check for this.  This check
   always fails when using VirtualBox on OSX, but it is safe to let
   the startup script to reset the prefix length to 16.

If for some reason, running of the provisioning script fails, you should bring the VM down before trying again:

::

    $ vagrant halt


Development Cycle
-----------------

The Vagrantfile in the Cilium repo root (hereon just ``Vagrantfile``),
always provisions Cilium build and install when the VM is started.
After the initial build and install you can do further building and
testing incrementally inside the VM. ``vagrant ssh`` takes you to the
Cilium source tree directory
(``/home/vagrant/go/src/github.com/cilium/cilium``) by default, and the
following commands assume that being your current directory.

Build
~~~~~

Assuming you have synced (rsync) the source tree after you have made
changes, or the tree is automatically in sync via NFS or guest
additions folder sharing, you can issue a build as follows:

::
   
    $ make

A successful build should be followed by running the unit tests:

::
   
    $ make tests

Install
~~~~~~~

After a successful build and test you can re-install Cilium by:

::

    $ sudo -E make install

Restart Cilium service
~~~~~~~~~~~~~~~~~~~~~~

To run the newly installed version of Cilium, restart the service:

::

    $ sudo service cilium restart

You can verify the service and cilium-agent status by the following
commands, respectively:

::
   
    $ service cilium status
    $ cilium status

Testsuite
~~~~~~~~~

After the new version of Cilium is running, you should run the runtime tests:

::
   
    $ sudo make runtime-tests

Building Documentation
~~~~~~~~~~~~~~~~~~~~~~

Whenever making changes to Cilium documentation you should check that you did not introduce any new warnings or errors, and also check that your changes look as you intended.  To do this you can build the docs:

::

    $ make -C Documentation html

After this you can browse the updated docs as HTML starting at
``Documentation\_build\html\index.html``.

Submitting a pull request
-------------------------

Contributions may be submitted in the form of pull requests against the
github repository at: `<https://github.com/cilium/cilium>`_

Before hitting the submit button, please make sure that the following
requirements have been met:

* The pull request and all corresponding commits have been equipped
  with a well written commit message which explains the reasoning
  and details of the change.
* You have added unit and/or runtime tests where feasible.
* You have tested the changes and checked for regressions by running
  the existing testsuite against your changes. See the "Testsuite"
  section for additional details.
* You have signed off on your commits, see the section "Developer's
  Certificate of Origin" for more details.

Release Process
---------------

Cilium schedules a major release every 3 months. Each major release is
performed by incrementing the `Y` in the version format `X.Y.0`. The group of
committers can decide to increment `X` instead to mark major milestones in
which case `Y` is reset to 0.

The following steps are performed to publish a release:

1. The master branch is set to the version `X.Y.90` at all times. This ensures
   that a development snapshot is considered more recent than a stable release
   at all times.
2. The committers can agree on a series of release candidates which will be
   tagged `vX.Y-rcN` in the master branch.
3. The committers declare the master branch ready for the release and fork the
   master branch into a release branch `vX.Y+1.0`.
4. The first commit in the release branch is to change the version to
   `X.Y+1.0`.
5. The next commit goes into the master branch and sets the version to
   `X.Y+1.90` to ensure that the master branch will be considered more recent
   than any stable release of the major release that is about to be published.

Stable releases
~~~~~~~~~~~~~~~

The committers can nominate commits pushed to the master as stable release
candidates in which case they will be backported to previous release branches.
Upon necessity, stable releases are published with the version `X.Y.Z+1`.

Criteria for the inclusion into stable release branches are:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium

Developer's Certificate of Origin
---------------------------------

To improve tracking of who did what, we've introduced a "sign-off"
procedure.

The sign-off is a simple line at the end of the explanation for the
commit, which certifies that you wrote it or otherwise have the right to
pass it on as open-source work. The rules are pretty simple: if you can
certify the below:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

then you just add a line saying:

::

   Signed-off-by: Random J Developer <random@developer.example.org>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

.. toctree::

   commit-access

