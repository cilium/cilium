# Vagrant

## Fast Path

To bring up a [vagrant](https://www.vagrantup.com/) VM with Cilium
plus all dependencies installed and running:

```
$ contrib/vagrant/start.sh [num_nodes]
```

This will bring up a master node plus an optional list of additional slave
nodes. The master node will run a consult agent with the slaves configured to
point to the consul of the master.

## Manual installation

Alternatively you can import the vagrant box `noironetworks/net-next` directly and
manually install Cilium:

  ```
  $ vagrant init noironetworks/net-next
  $ vagrant up
  $ vagrant ssh [...]
  $ cd go/src/github.com/cilium/cilium/
  $ make
  $ sudo make install
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
