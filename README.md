
## Installation instructions

1. Bring up vagrant environment

   This will bring up two VMs, node1 and node2, and compiles cilium-net
   inside the VMs.

   ```
   $ vagrant up --provider libvirt
   $ vagrant ssh
   ```

   If you have changed any source code or want to recompile the
   daemon and plugins, you may reprovision the environment at
   any time with:
   ```
   $ vagrant reload --provision
   ```

2. Run the daemon

   ```
   $ sudo make run-cilium-daemon
   [...]
   ```

3. Run the plugin

   ```
   $ sudo make run-docker-plugin
   [...]
   ```

4. Run a container

   ```
   $ docker network create --driver cilium --ipam-driver cilium test-net
   $ docker run -ti --rm --net test-net ubuntu bash
   ```

## Detailed Instructions

### Setting up direct routing mode

This mode uses native IPv6 connectivty between the container hosts and does
not rely on encapsulation protocols.

1. Compile all components

  ```
  $ make
  ```

2. Run `cilium-net` in direct mode:

  ```
  $ cd cilium-net-daemon
  $ sudo ./run.sh -d eth0
  [...]
  $ cd docker-plugin
  $ sudo ./run.sh
  ```

  This will install a BPF program on eth0 which will pick packets destined for
  local containers.

3. Install routes to other container hosts

  In order to reach containers on other hosts. A route must exist, pointing the
  node subnet to the respective host. This can be achieved by running a routing
  daemon or by installing the routes manually:

  ```
  $ ip -6 route add beef::c0a8:79d9:0/128 dev eth0
  $ ip -6 route add beef::c0a8:79d9:0/112 via beef::c0a8:79d9:0
  ```
  In this example, `beef::c0a8:79d9:0` is the IPv6 node address of a container
  host. These routes must be configured on each other host.
