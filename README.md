
## Installation instructions

1. Bring up vagrant environment

   ```
   $ vagrant up --provider libvirt
   $ vagrant ssh
   ```

2. Compile the docker plugin and tools

   ```
   $ make
   ```

3. Run the daemon

   ```
   $ sudo make run-cilium-daemon
   [...]
   ```

4. Run the plugin

   ```
   $ sudo make run-docker-plugin
   [...]
   ```

5. Run a container

   ```
   $ docker network create --driver cilium --ipam-driver cilium test-net
   $ docker run -ti --rm --net test-net ubuntu bash
   ```
