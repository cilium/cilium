# Do not upgrade to alpine 3.13 as its nslookup tool returns 1, instead of 0
# for domain name lookups.
FROM docker.io/library/alpine:3.12.7@sha256:36553b10a4947067b9fbb7d532951066293a68eae893beba1d9235f7d11a20ad

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
