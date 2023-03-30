#!/bin/bash
set -e
DRIVER_NAME_NO_EXT="hailo_pci"
dkms status $DRIVER_NAME_NO_EXT | sed -n "s/^$DRIVER_NAME_NO_EXT[^0-9]\{1,2\}\([0-9]\+\.[0-9]\+\.[0-9]\+\).*$/\1/p" | xargs -I{} dkms remove $DRIVER_NAME_NO_EXT/{} --all
rm -rf /usr/src/$DRIVER_NAME_NO_EXT-*