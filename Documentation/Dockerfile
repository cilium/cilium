# Container for making it easier to build the documentation via Docker.
FROM ubuntu:16.04
ENV DOCS_DIR=/srv/Documentation
ENV API_DIR=/srv/api

WORKDIR $DOCS_DIR
ADD Documentation $DOCS_DIR
ADD api $API_DIR

RUN apt-get update && \
      apt-get install -y git make python-sphinx python-pip \
      # PDF dependencies use a lot of space, left here for others.
      # latexmk texlive-latex-extra
      && apt-get clean && \
      pip install --upgrade pip && \
      pip install -r $DOCS_DIR/requirements.txt && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
