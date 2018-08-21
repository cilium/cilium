FROM fedora:27

LABEL maintainer="Tony Lambiris <tony@criticalstack.com>"

RUN curl -sSL -o /etc/yum.repos.d/vbatts-bazel-fedora-27.repo \
	https://copr.fedorainfracloud.org/coprs/vbatts/bazel/repo/fedora-27/vbatts-bazel-fedora-27.repo

RUN dnf -y update && \
	dnf -y install fedora-packager fedora-review golang go-bindata gettext \
		git glibc-devel.x86_64 glibc-devel.i686 cmake bazel libtool wget \
		gcc-c++ elfutils-libelf-devel libstdc++-static && \
    mkdir -p /opt/cilium/

WORKDIR /opt/cilium

ADD . /opt/cilium

VOLUME ["/output"]
ENTRYPOINT /opt/cilium/create_rpm.sh
