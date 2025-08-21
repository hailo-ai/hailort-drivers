#!/bin/bash
set -e
DRIVER_NAME_NO_EXT="hailo1x_pci"
DRIVER_NAME="hailo1x_pci.ko"

rm -rf /var/lib/dkms/$DRIVER_NAME_NO_EXT/*
rm -rf /lib/modules/*/updates/dkms/$DRIVER_NAME
rm -rf /usr/src/$DRIVER_NAME_NO_EXT-*
