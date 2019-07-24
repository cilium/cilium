FROM docker.io/library/golang:1.12.7
RUN curl https://raw.githubusercontent.com/golang/dep/v0.5.4/install.sh | sh
CMD dep ensure -v
