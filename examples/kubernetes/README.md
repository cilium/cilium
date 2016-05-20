# Kubernetes Network Policy + Cilium

This tutorial will show you how you can have full IPv6 connectivity between
docker containers orchestrated by kubernetes. All your services will be able to
talk with their producers by only using the service name instead of static IPs.
The containers started by kubernetes will have some labels where the policy for those labels
will be pushed to the [v1beta1 kubernetes network policy API](https://github.com/kubernetes/kubernetes/blob/master/docs/proposals/network-policy.md)
and enforced with Cilium.

## Requirements

 - Cilium Vagrant Image
 - IPv6 connectivity between host and Cilium Vagrant VM
 - Setup cilium-net-daemon in direct routing mode
 - Tested with `kubernetes-v1.3.0-alpha.4` patched with `kubernetes-v1.3.0-alpha.4.patch`

### IPv6 connectivity between host and Cilium Vagrant VM - VirtualBox provider

1 - Search for the interface that connects to your VMs, it should be something like
`vboxnet#` and have the IP network `192.168.33.0/24`.

```bash
HOST $ ip address show dev vboxnet0
5: vboxnet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:00:27:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.33.1/24 brd 192.168.33.255 scope global vboxnet0
       valid_lft forever preferred_lft forever
```

2 - Set the IPv6 disable to 0 for that vboxnet interface

```bash
HOST $ sudo sysctl net.ipv6.conf.vboxnet0.disable_ipv6=0
```

3 - Set an IPv6 address in your host

```bash
HOST $ sudo ip -6 address add beef::dead:fffd/112 dev vboxnet0
```

4 - Set an IPv6 address in your VM that connects to your host, it should have the
IP network `192.168.33.0/24`:
```bash
VM $ ip address show dev eth1
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:e3:45:f2 brd ff:ff:ff:ff:ff:ff
    inet 192.168.33.13/24 brd 192.168.33.255 scope global eth1
       valid_lft forever preferred_lft forever
VM $
VM $ sudo ip -6 address add beef::dead:fffe/112 dev eth1
```

5 - You should be able to ping the host from the VM

```bash
VM $ ping6 beef::dead:fffd
PING beef::dead:fffd(beef::dead:fffd) 56 data bytes
64 bytes from beef::dead:fffd: icmp_seq=1 ttl=64 time=0.691 ms
...
```

6 - Add the IPv6 route in the host so the host can reach the containers:

```bash
HOST $ sudo ip -6 route add beef::a00:20f:0/112 via beef::dead:fffe
```

### Setup cilium-net-daemon in direct routing mode

Edit the file `/etc/init.d/cilium-net-daemon.conf` and make sure it has the
`-d` option set with the interface that you set up the IPv6.

```bash
VM $ sudo cat /etc/init/cilium-net-daemon.conf
exec cilium -D daemon -d eth1
```

Don't forget to restart the service: `sudo service cilium-net-daemon restart`

## Edit the env-kube.sh

Source the `env-kube.sh` file to your console and run
`~/kubernetes/hack/local-up-cluster.sh`:

```bash
VM $ source ./env-kube.sh
VM $ ~/kubernetes/hack/local-up-cluster.sh
```

Wait until kubernetes has started (you'll see a message similar to):
```
To start using your cluster, open up another terminal/tab and run:
```

## Setting up the 3rd party extensions

Kubernetes is already running with `--runtime-config=extensions/v1beta1=true,extensions/v1beta1/thirdpartyresources=true`
so we'll first put some kubernetes network policies. Simply run `./0-policy.sh` that will
take care of it.

```bash
VM $ ./0-policy.sh
```

## Setting up SkyDNS and Kube2Sky

Open a new terminal since kubernetes will be running on previous one on the
foreground.

Run `./1-dns.sh`, if everything went fine you should something similar:
_it might take a while on the first run since kubernetes is starting and the images are
being pulled._

```bash
VM $ ./1-dns.sh
namespace "kube-system" created
replicationcontroller "kube-dns-v11" created
Getting DNS IP. Attempt 1/10...
Getting DNS IP. Attempt 2/10...
DNS IP found: beef::a00:20f:17
```

## Setting up guestbook example

Next run `2-guestbook.sh` and you should be something similar to this:

```bash
VM $ ./2-guestbook.sh
replicationcontroller "redis-master" created
service "redis-master" created
replicationcontroller "redis-slave" created
service "redis-slave" created
replicationcontroller "guestbook" created
service "guestbook" created
Getting Guestbook IP. Attempt 1/10...
Getting Guestbook IP. Attempt 2/10...
Guestbook IP found! Open in your host the address
http://[beef::a00:20f:21]:3000
```

Open your browser and you should see something similar to this:

![browser](browser.png)
