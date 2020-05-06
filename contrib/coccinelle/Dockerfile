FROM docker.io/library/alpine:3.11

LABEL maintainer="maintainer@cilium.io"

ENV COCCINELLE_VERSION 1.0.8

RUN apk add -t .build_apks curl autoconf automake gcc libc-dev ocaml ocaml-dev ocaml-ocamldoc ocaml-findlib && \
    apk add make python bash && \
    curl -sS -L https://github.com/coccinelle/coccinelle/archive/$COCCINELLE_VERSION.tar.gz -o coccinelle.tar.gz && \
    tar xvzf coccinelle.tar.gz && rm coccinelle.tar.gz && \
    cd coccinelle-$COCCINELLE_VERSION && \
    ./autogen && \
    ./configure --disable-ocaml --disable-pcre-syntax && \
    make && make install-spatch install-python && \
    cd .. && rm -r coccinelle-$COCCINELLE_VERSION && \
    strip `which spatch` && \
    apk del .build_apks
