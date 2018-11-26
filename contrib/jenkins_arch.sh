#!/bin/sh
# this is a dispatcher script which will call the arch-specific
# script based on the arch specified as command line argument

arch="$1"

if [ "x$arch" = "x" ]; then
	echo "Error: You have to specify the architecture as first argument, e.g. $0 amd64"
	exit 2
fi

if [ ! -d "./contrib" ]; then
  echo "Run ./contrib/jenkins_arch.sh from the root of the libosmocore tree"
  exit 1
fi

set -x

gcc --version

set -e

case "$arch" in

  amd64)
    ./contrib/jenkins_amd64.sh
  ;;

  arm|arm-none-eabi)
    ./contrib/jenkins_arm.sh
  ;;

  *)
    set +x
    echo "Unexpected architecture '$arch'"
    exit 1
  ;;
esac
