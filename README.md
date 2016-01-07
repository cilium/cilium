
## Installation instructions

1. Bring up vagrant environment

```
$ vagrant up --provider libvirt
$ vagrant ssh
```

2. Compile the docker plugin

```
$ cd cilium-net/docker-plugin
$ make deps
$ make
```

3. Run the plugin

```
$ make run
```

4. Run a container

```
$ docker network create --driver cilium --ipam-driver cilium test-net
$ docker run -ti --rm --net test-net ubuntu bash
```
