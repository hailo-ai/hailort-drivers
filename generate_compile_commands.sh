#!/bin/bash

HOST_COMPONENTS="pcie"
DEVICE_COMPONENTS="pci_ep integrated_nnc"

source ../tools/scripts/hailo10_env_vars.sh

if [ -z "$TOOLCHAIN_IMAGE_NAME" ]; then
    echo "TOOLCHAIN_IMAGE_NAME is not set. Please set it before running this script."
    exit 1
fi

TOOLCHAIN_PATH=`realpath ../internals/toolchains/.toolchains/linux.hailo-kirkstone-a53/$TOOLCHAIN_IMAGE_NAME`

BASE_DIR=`pwd`
CCJ=compile_commands.json

rm -f $CCJ && touch $CCJ && echo "{}" > $CCJ

for component in $HOST_COMPONENTS; do
    cd ./linux/$component
    bear --append --output $BASE_DIR/$CCJ -- \
    make clean all
    cd $BASE_DIR
done;

source $TOOLCHAIN_PATH/environment-setup-armv8a-poky-linux

for component in $DEVICE_COMPONENTS; do
    cd ./linux/$component
    bear --append --output $BASE_DIR/$CCJ -- \
    make clean all KERNEL_DIR=$TOOLCHAIN_PATH/sysroots/armv8a-poky-linux/usr/src/kernel
    cd $BASE_DIR
done;
