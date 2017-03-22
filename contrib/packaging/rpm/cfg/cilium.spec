Name:       cilium
Version:    ${VERSION}
Release:    1%{?dist}
Summary:    BPF & XDP for containers
License:    Apache
URL:        https://github/cilium/cilium
BuildArch:  x86_64
Source0:    %{name}-%{version}.tar.gz
Requires:   docker-engine >= 1.12, clang >= 3.8, clang < 3.9, glibc-devel(x86-32), iproute >= 4.6, kernel >= 4.8

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
/etc/init/cilium.conf
/etc/init/cilium-policy-watcher.conf
/etc/sysconfig/cilium
/lib/systemd/system/cilium-consul.service
/lib/systemd/system/cilium-docker.service
/lib/systemd/system/cilium-etcd.service
/lib/systemd/system/cilium.service
/opt/cni/bin/cilium-cni
/usr/bin/cilium
/usr/bin/cilium-agent
/usr/bin/cilium-docker

%changelog
* Wed Oct 12 2016 Andre Martins <andre@cilium.io> - ${VERSION}
- Initial version of the package
