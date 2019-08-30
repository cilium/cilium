#!/bin/bash

arg1=$1

BINDATA_FILE=bindata.go
REQUIRED_GO_VERSION=$(cat ../GO_VERSION)

if [[ "$arg1" == "apply" ]]; then
  NEW_SHA1SUM=`sha1sum ${BINDATA_FILE} | awk '{ print $1}'`
  GO_VERSION_USED=`go version | awk '{ print $3 }'`
  BPF_FILES=`git ls-files ../bpf/ | grep -v .gitignore | tr "\n" ' '`
  sed -i "s/GO_BINDATA_SHA1SUM=.*/GO_BINDATA_SHA1SUM=${NEW_SHA1SUM}/g" bpf.sha
  sed -i "s#BPF_FILES=.*#BPF_FILES=${BPF_FILES}#g" bpf.sha
  exit 0
fi

GO_BINDATA_SHA1SUM=$arg1

if [[ $GO_BINDATA_SHA1SUM == "" ]]; then
  echo "please provide a sha1sum for the expected bindata."
  exit 1
fi

if echo "$GO_BINDATA_SHA1SUM bindata.go" | sha1sum -c --quiet; then
  exit 0
fi

echo "########################################################################"
echo ""
echo "                  ERROR: bindata.go is out of date."
echo ""
echo " This can happen for two reasons:"
echo " 1. You are using a go-bindata binary compiled with a different version"
echo "    of golang (not ${REQUIRED_GO_VERSION}). If so, please up/downgrade."
echo ""
echo " 2. You have made changes to the bpf/ directory. Please run the"
echo "    following command to update the SHA in daemon/bpf.sha:"
echo ""
echo "    $ make -C daemon apply-bindata"
echo ""
echo "########################################################################"

exit 1
