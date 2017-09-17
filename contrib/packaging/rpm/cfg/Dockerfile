FROM fedora:25

LABEL maintainer "Marcin Skarbek <marcin@skarbek.name>"

RUN echo "deltarpm=0" >> /etc/dnf/dnf.conf &&\
    curl -o /etc/yum.repos.d/mskarbek-golang-for-cilium-fedora-25.repo https://copr.fedorainfracloud.org/coprs/mskarbek/golang-for-cilium/repo/fedora-25/mskarbek-golang-for-cilium-fedora-25.repo &&\
    dnf -y update &&\
    dnf -y install fedora-packager fedora-review golang gettext &&\
    dnf -y install glibc-devel.i686 &&\
    dnf clean all

ADD . /root

RUN /root/create-rpm.sh
