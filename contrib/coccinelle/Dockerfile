FROM docker.io/library/alpine:3.13.1@sha256:08d6ca16c60fe7490c03d10dc339d9fd8ea67c6466dea8d558526b1330a85930

LABEL maintainer="maintainer@cilium.io"

ENV COCCINELLE_VERSION 1.0.8

RUN apk add -t .build_apks curl autoconf automake gcc libc-dev ocaml ocaml-dev ocaml-ocamldoc ocaml-findlib && \
    apk add make python3 bash && \
    curl -sS -L https://github.com/coccinelle/coccinelle/archive/$COCCINELLE_VERSION.tar.gz -o coccinelle.tar.gz && \
    tar xvzf coccinelle.tar.gz && rm coccinelle.tar.gz && \
    cd coccinelle-$COCCINELLE_VERSION && \
    ./autogen && \
    ./configure --disable-ocaml --disable-pcre-syntax --with-python=python3 && \
    make && make install-spatch install-python && \
    cd .. && rm -r coccinelle-$COCCINELLE_VERSION && \
    strip `which spatch` && \
    apk del .build_apks
