#!/bin/bash

usage () {
    echo "Remove DKMS PCIe driver installation"
    echo ""
    echo "Usage: $0 [-h] -v DRIVER_VERSION [-k KERNEL_VERSION] [-r]"
    echo " - -h: display this help."
    echo ""
    echo " - -v: Driver version to remove. Use 'dkms status' to see which versions are installed."
    echo ""
    echo " - -k: Kernel version to remove. If not specified, the current version will be selected."
    echo ""
    echo " - -r: Remove driver source code located in /usr/src/."
    echo "       Use this only when there should be no more drivers installed for the selected version."
    echo ""
    exit 1
}

DRIVER_NAME="hailo_pci"
DRIVER_VERSION=""
KERNEL_VERSION=`uname -r`
SHOULD_REMOVE_SOURCE=""

while getopts "hv:k:r" arg; do
    case $arg in
    h)
        usage
        ;;
    v)
        DRIVER_VERSION="$OPTARG"
        ;;
    k)
        KERNEL_VERSION="$OPTARG"
        ;;
    r)
        SHOULD_REMOVE_SOURCE="True"
        ;;
    *)
        usage
        ;;
    esac
done

if [ -z "$DRIVER_VERSION" ]; then
    usage
    exit 1
fi

# remove installation
dkms remove -m $DRIVER_NAME -v $DRIVER_VERSION -k $KERNEL_VERSION

if [ -n "$SHOULD_REMOVE_SOURCE" ]; then
    rm -rf /usr/src/$DRIVER_NAME-$DRIVER_VERSION
fi