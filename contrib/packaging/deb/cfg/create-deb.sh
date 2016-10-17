#!/usr/bin/env bash

create_deb(){
    cp "cilium-$VERSION.tar.gz" ../"cilium_$VERSION.orig.tar.gz"
    mv "cilium-$VERSION.tar.gz" ..
    envsubst \\\$VERSION < "debian/control" > "debian/control"
    debuild -e DESTDIR -e GOPATH -e GOROOT -e PKG_BUILD -e VERSION \
        --prepend-path "$GOROOT/bin" -us -uc
}

create_deb
