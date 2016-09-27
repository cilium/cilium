# Vagrant

## Using the provided Vagrantfile

To bring up a [vagrant](https://www.vagrantup.com/) VM with Cilium plus
dependencies installed, run:

```
$ contrib/vagrant/start.sh
```

This will bring up a master node plus the configured  number of additional slave
nodes. The master node will run a consul agent with the slaves configured to
point to it.

### Options

The following environment variables can be set to customize the VMs brought up
by vagrant:
 * NUM_NODES=n: Number of child nodes you want to start
 * RELOAD=1: Issue a `vagrant reload` instead of `vagrant up`
 * NFS=1: Use NFS for vagrant shared directories instead of rsync
 * K8S=1: Build & install kubernetes on the nodes
 * IPV4=1: Run Cilium with IPv4 enabled
 * VAGRANT_DEFAULT_PROVIDER={virtualbox | libvirt | ...}

Example:

 ```
 $ IPV4=1 K8S=1 NUM_NODES=3 contrib/vagrant/start.sh
 ```

If you have any issue with the provided vagrant box `noironetworks/net-next`
if your need a different box format, you may build the box yourself using
packer:

```
$ cd contrib/packer-scripts/ubuntu-14.04/
$ make build-vbox [See Makefile for other targets]
$ vagrant box add --name noironetworks/net-next [...]
```

## Manual installation

Alternatively you can import the vagrant box `noironetworks/net-next` directly
and manually install Cilium:

  ```
  $ vagrant init noironetworks/net-next
  $ vagrant up
  $ vagrant ssh [...]
  $ cd go/src/github.com/cilium/cilium/
  $ make
  $ sudo make install
  $ sudo cp contrib/upstart/* /etc/init/
  $ sudo usermod -a -G cilium vagrant
  $ sudo service cilium-net-daemon restart
  ```

## (Re)building the box

To manually build the vagrant boxes using packer:

```
$ cd contrib/packer-scripts/ubuntu-14.04/
$ make build-vbox
$ make build-libvirt
$ make build-...
```
