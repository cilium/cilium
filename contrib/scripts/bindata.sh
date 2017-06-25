#!/bin/bash

arg1=$1

BINDATA_FILE=bindata.go

if [[ "$arg1" == "apply" ]]; then
  NEW_SHA1SUM=`sha1sum ${BINDATA_FILE} | awk '{ print $1}'`
  GO_VERSION_USED=`go version | awk '{ print $3 }'`
  sed -i "s/GO_BINDATA_SHA1SUM=.*/GO_BINDATA_SHA1SUM=${NEW_SHA1SUM}/g" Makefile
  sed -i "s/GO_VERSION_USED=.*/GO_VERSION_USED=${GO_VERSION_USED}/g" Makefile
  exit 0
fi

GO_BINDATA_SHA1SUM=$arg1

if [[ $GO_BINDATA_SHA1SUM == "" ]]; then
  echo "please provide a sha1sum for the expected bindata."
  exit 1
fi

if echo "$GO_BINDATA_SHA1SUM bindata.go" | sha1sum -c; then
  exit 0
fi

echo "########################################################################"
echo ""
echo "                  ERROR: bindata.go is out of date."
echo ""
echo "  Use 'make -C daemon apply-bindata' to update the SHA in the Makefile."
echo "########################################################################"

exit 1
