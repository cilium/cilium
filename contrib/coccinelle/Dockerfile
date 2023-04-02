FROM docker.io/library/alpine:3.16.0@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c

LABEL maintainer="maintainer@cilium.io"

ENV COCCINELLE_VERSION 1.1.1
ENV PYTHONPATH /usr/local/lib/coccinelle/python

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
