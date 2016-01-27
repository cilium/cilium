
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
