Vagrant
=======

Using the provided Vagrantfile
------------------------------

To bring up a `vagrant <https://www.vagrantup.com/>`__ VM with Cilium
plus dependencies installed, run:

::

    $ contrib/vagrant/start.sh

This will bring up a master node plus the configured number of
additional worker nodes. The master node will run a consul agent with
the slaves configured to point to it.

Options
~~~~~~~

The following environment variables can be set to customize the VMs
brought up by vagrant: \* ``NWORKERS=n``: Number of child nodes you want
to start with the master, default 0. \* ``RELOAD=1``: Issue a
``vagrant reload`` instead of ``vagrant up`` \* ``NFS=1``: Use NFS for
vagrant shared directories instead of rsync \* ``K8S=1``: Build &
install kubernetes on the nodes \* ``IPV4=1``: Run Cilium with IPv4
enabled \* VAGRANT\_DEFAULT\_PROVIDER={virtualbox \| libvirt \| ...}

If you want to start the VM with cilium enabled with IPv4, with
kubernetes installed and plus a worker, run:

``$ IPV4=1 K8S=1 NWORKERS=1 contrib/vagrant/start.sh``

If you have any issue with the provided vagrant box
``noironetworks/net-next`` if your need a different box format, you may
build the box yourself using packer:

::

    $ cd contrib/packer-scripts/ubuntu-16.10/
    $ make build-vbox [See Makefile for other targets]
    $ vagrant box add --name noironetworks/net-next [...]

Manual installation
-------------------

Alternatively you can import the vagrant box ``noironetworks/net-next``
directly and manually install Cilium:

``$ vagrant init noironetworks/net-next   $ vagrant up   $ vagrant ssh [...]   $ cd go/src/github.com/cilium/cilium/   $ make   $ sudo make install   $ sudo cp contrib/upstart/* /etc/init/   $ sudo usermod -a -G cilium vagrant   $ sudo service cilium restart``

(Re)building the box
--------------------

To manually build the vagrant boxes using packer:

::

    $ cd contrib/packer-scripts/ubuntu-16.10/
    $ make build-vbox
    $ make build-libvirt
    $ make build-...
