FROM fedora:28

LABEL maintainer="Tony Lambiris <tony@criticalstack.com>"

RUN curl -sSL -o /etc/yum.repos.d/vbatts-bazel-fedora-28.repo \
	https://copr.fedorainfracloud.org/coprs/vbatts/bazel/repo/fedora-28/vbatts-bazel-fedora-28.repo

RUN dnf -y update && \
	dnf -y install fedora-packager fedora-review golang gettext \
		git glibc-devel.x86_64 cmake bazel libtool wget \
		clang make gcc-c++ libstdc++-static && \
    mkdir -p /opt/cilium/

WORKDIR /opt/cilium

ADD . /opt/cilium

VOLUME ["/output"]
ENTRYPOINT /opt/cilium/create_rpm.sh
