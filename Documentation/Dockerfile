FROM docker.io/library/python:3.7.5-alpine3.10

LABEL maintainer="maintainer@cilium.io"

RUN apk add --no-cache --virtual --update \
    aspell-en \
    bash \
    ca-certificates \
    enchant \
    git \
    py-pip \
    python \
    sphinx-python \
    && true

ADD ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt