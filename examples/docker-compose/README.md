# Cilium with docker-compose

This tutorial will show you how you can have full IPv6 connectivity between
docker containers using the cilium docker image.

## Requirements

 - docker-compose (>=1.7.1)
 - Linux-kernel (>=4.8.0)

### Download docker-compose.yml

Download the `docker-compose.yml` [here](docker-compose.yml) and
edit the IP address with one that is not a loopback IP address.

```yml
version: '2'
services:
  cilium:
    image: noironetworks:cilium-ubuntu-15-10
    command: cilium -D daemon run -d eth1 --ui-addr tcp://192.168.33.21:8086
    volumes:
...
```

### Run docker-compose

```
$ docker-compose up
```

### Create a cilium network in docker

```
$ docker network create --ipam-driver cilium --driver cilium cilium
```

### Start and run containers

```
$ docker run -d --name wine --net cilium --label io.cilium.service.wine noironetworks/nettools sleep 30000
$ docker run -d --name bar --net cilium --label io.cilium.service.bar noironetworks/nettools sleep 30000
$ docker run -d --name client --net cilium --label io.cilium.service.client noironetworks/nettools sleep 30000
```

### Open your browser on the same address as written before

![Cilium dashboard](cilium-docker-1.png)

Click on the `endpoints` tab and then on the node that has the `io.cilium.service.bar` label.

![Cilium dashboard](cilium-docker-2.png)

Copy its IPv6 address and try to ping it from the `client` container where the ping will fail.

```
$ docker exec -ti client ping6 -c 4 f00d::c0a8:2115:74ca
PING f00d::c0a8:2115:74ca(f00d::c0a8:2115:74ca) 56 data bytes

--- f00d::c0a8:2115:74ca ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3095ms
```

The network lack a policy which allows both containers to speak with each other, in fact,
we only need the container `client` to consume container `bar` and `bar` to consume
container `wine`.

### Insert a valid policy into the daemon

Go to the browser again and open the policy tab. Choose the policy file provided
[here](docker.policy) and upload it.

![Cilium dashboard](cilium-docker-3.png)

Try pinging again the container `bar` from `client` and you can see the pings are successfully
made.

```
$ docker exec -ti client ping6 -c 4 f00d::c0a8:2115:74ca
PING f00d::c0a8:2115:74ca(f00d::c0a8:2115:74ca) 56 data bytes
64 bytes from f00d::c0a8:2115:74ca: icmp_seq=1 ttl=63 time=0.043 ms
64 bytes from f00d::c0a8:2115:74ca: icmp_seq=2 ttl=63 time=0.054 ms
64 bytes from f00d::c0a8:2115:74ca: icmp_seq=3 ttl=63 time=0.083 ms
64 bytes from f00d::c0a8:2115:74ca: icmp_seq=4 ttl=63 time=0.066 ms

--- f00d::c0a8:2115:74ca ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2998ms
```

![Cilium dashboard](cilium-docker-4.png)

If you try to ping from `client` directly to `wine` it won't be possible since the policy
doesn't allow it.