Vagrant
=======

Using the provided Vagrantfile
------------------------------

.. note::

   You need to run Vagrant version 1.8.3 or later or you will run into issues
   booting the Ubuntu 16.10 base image.

To bring up a `vagrant <https://www.vagrantup.com/>`__ VM with Cilium
plus dependencies installed, run:

::

    $ contrib/vagrant/start.sh

This will create and run a vagrant VM based on the base box
``cilium/ubuntu-16.10``. The box is currently available for the
following providers:

* libvirt
* virtualbox

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

::

	$ IPV4=1 K8S=1 NWORKERS=1 contrib/vagrant/start.sh

If you have any issue with the provided vagrant box
``cilium/ubuntu-16.10`` if your need a different box format, you may
build the box yourself using the [packer scripts](https://github.com/cilium/packer-ubuntu-16.10)

Manual installation
-------------------

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
        $ sudo service cilium restart``
