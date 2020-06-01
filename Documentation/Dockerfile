FROM docker.io/library/python:3.7.5-alpine3.10

LABEL maintainer="maintainer@cilium.io"

ENV DOCS_DIR=/srv/Documentation
ENV API_DIR=/srv/api

ADD ./requirements.txt $DOCS_DIR/requirements.txt

ENV PACKAGES="\
    bash \
    nodejs \
    npm \
    ca-certificates \
    make \
    git \
    python \
    py-pip \
    sphinx-python \
    enchant \
    aspell-en \
"
RUN apk add --no-cache --virtual --update $PACKAGES && \
    pip install --upgrade pip && \
    pip install -r $DOCS_DIR/requirements.txt

WORKDIR $DOCS_DIR
ADD _api $API_DIR
ADD . $DOCS_DIR
