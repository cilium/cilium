Name:       cilium
Version:    ${VERSION}
Release:    1%{?dist}
Summary:    BPF & XDP for containers
License:    Apache
URL:        https://github/cilium/cilium
BuildArch:  x86_64
Source0:    %{name}-%{version}.tar.gz
Requires:   docker-engine >= 1.12, clang >= 3.8, glibc-devel(x86-32), iproute >= 4.6, kernel >= 4.8

%description
Cilium provides fast in-kernel networking and security policy enforcement
for containers based on eBPF programs generated on the fly. It is an
experimental project aiming at enabling emerging kernel technologies such
as BPF and XDP for containers.

%pre
if ! grep -q cilium /etc/group; then groupadd cilium; fi

%build
make

%install
export DESTDIR=%{buildroot}
%make_install

mkdir -p "%{buildroot}/lib/systemd/system"
mkdir -p "%{buildroot}/etc/sysconfig"

cp contrib/systemd/*.service "%{buildroot}/lib/systemd/system"
chmod 644 %{buildroot}/lib/systemd/system/*

cp contrib/systemd/cilium "%{buildroot}/etc/sysconfig"
chmod 644 "%{buildroot}/etc/sysconfig/cilium"

mkdir -p "%{buildroot}/etc/init"

cp contrib/upstart/* "%{buildroot}/etc/init"
chmod 644 %{buildroot}/etc/init/*

%files
/etc/bash_completion.d/cilium
/etc/init/cilium-consul.conf
/etc/init/cilium-docker.conf
/etc/init/cilium-etcd.conf
/etc/init/cilium-net-daemon.conf
/etc/init/cilium-policy-watcher.conf
/etc/init/cilium-socket-proxy.conf
/etc/sysconfig/cilium
/lib/systemd/system/cilium-consul.service
/lib/systemd/system/cilium-docker.service
/lib/systemd/system/cilium-etcd.service
/lib/systemd/system/cilium-net-daemon.service
/opt/cni/bin/cilium-cni
/usr/bin/cilium
/usr/bin/cilium-docker
/usr/lib/cilium/bpf_lb.c
/usr/lib/cilium/bpf_lxc.c
/usr/lib/cilium/bpf_netdev.c
/usr/lib/cilium/bpf_overlay.c
/usr/lib/cilium/include/bpf/api.h
/usr/lib/cilium/include/iproute2/bpf_elf.h
/usr/lib/cilium/include/linux/bpf.h
/usr/lib/cilium/include/linux/bpf_common.h
/usr/lib/cilium/include/linux/byteorder.h
/usr/lib/cilium/include/linux/byteorder/big_endian.h
/usr/lib/cilium/include/linux/byteorder/little_endian.h
/usr/lib/cilium/include/linux/icmp.h
/usr/lib/cilium/include/linux/icmpv6.h
/usr/lib/cilium/include/linux/if_arp.h
/usr/lib/cilium/include/linux/if_ether.h
/usr/lib/cilium/include/linux/in.h
/usr/lib/cilium/include/linux/in6.h
/usr/lib/cilium/include/linux/ioctl.h
/usr/lib/cilium/include/linux/ip.h
/usr/lib/cilium/include/linux/ipv6.h
/usr/lib/cilium/include/linux/perf_event.h
/usr/lib/cilium/include/linux/swab.h
/usr/lib/cilium/include/linux/tcp.h
/usr/lib/cilium/include/linux/type_mapper.h
/usr/lib/cilium/include/linux/udp.h
/usr/lib/cilium/init.sh
/usr/lib/cilium/join_ep.sh
/usr/lib/cilium/leave_ep.sh
/usr/lib/cilium/lib/arp.h
/usr/lib/cilium/lib/common.h
/usr/lib/cilium/lib/conntrack.h
/usr/lib/cilium/lib/csum.h
/usr/lib/cilium/lib/dbg.h
/usr/lib/cilium/lib/drop.h
/usr/lib/cilium/lib/eth.h
/usr/lib/cilium/lib/events.h
/usr/lib/cilium/lib/geneve.h
/usr/lib/cilium/lib/icmp6.h
/usr/lib/cilium/lib/ipv4.h
/usr/lib/cilium/lib/ipv6.h
/usr/lib/cilium/lib/l3.h
/usr/lib/cilium/lib/l4.h
/usr/lib/cilium/lib/lb.h
/usr/lib/cilium/lib/lxc.h
/usr/lib/cilium/lib/maps.h
/usr/lib/cilium/lib/nat46.h
/usr/lib/cilium/lib/policy.h
/usr/lib/cilium/lib/policy_map.h
/usr/lib/cilium/lib/utils.h
/usr/lib/cilium/probes/skb_change_tail.c
/usr/lib/cilium/run_probes.sh
/usr/lib/cilium/ui/css/bootstrap-3.3.6.min.css
/usr/lib/cilium/ui/css/bootstrap-theme-3.3.6.min.css
/usr/lib/cilium/ui/css/cilium.css
/usr/lib/cilium/ui/css/vis.min.css
/usr/lib/cilium/ui/fonts/glyphicons-halflings-regular.eot
/usr/lib/cilium/ui/fonts/glyphicons-halflings-regular.svg
/usr/lib/cilium/ui/fonts/glyphicons-halflings-regular.ttf
/usr/lib/cilium/ui/fonts/glyphicons-halflings-regular.woff
/usr/lib/cilium/ui/fonts/glyphicons-halflings-regular.woff2
/usr/lib/cilium/ui/images/cilium.ico
/usr/lib/cilium/ui/images/cilium.svg
/usr/lib/cilium/ui/images/loading.gif
/usr/lib/cilium/ui/index.html
/usr/lib/cilium/ui/js/bootstrap-3.3.6.min.js
/usr/lib/cilium/ui/js/cilium.js
/usr/lib/cilium/ui/js/jquery-2.2.4.min.js
/usr/lib/cilium/ui/js/vis.animatetraffic.js
/usr/lib/cilium/ui/js/vis.min.js

%changelog
* Wed Oct 12 2016 Andre Martins <andre@cilium.io> - ${VERSION}
- Initial version of the package
