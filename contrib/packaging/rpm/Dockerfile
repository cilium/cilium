FROM fedora:26

LABEL maintainer="Tony Lambiris <tony@criticalstack.com>"

RUN dnf -y update && \
	dnf -y install fedora-packager fedora-review golang go-bindata gettext \
		git glibc-devel.x86_64 glibc-devel.i686 && \
    mkdir -p /opt/cilium/

WORKDIR /opt/cilium

ADD . /opt/cilium

VOLUME ["/output"]
ENTRYPOINT /opt/cilium/create_rpm.sh
