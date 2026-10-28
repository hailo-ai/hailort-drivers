#!/bin/bash

TOOLCHAIN_IMAGE_NAME=source_SJ74FN0Y # Taken from bkc-info.json. TODO: make this better.
TOOLCHAIN_PATH=`realpath ../internals/toolchains/.toolchains/linux.hailo-kirkstone-a53/$TOOLCHAIN_IMAGE_NAME`
TOOLCHAIN_ROOT=$TOOLCHAIN_PATH/sysroots/armv8a-poky-linux/usr/src/kernel

CCJ=compile_commands.json

rm -f $CCJ && touch $CCJ && echo "{}" > $CCJ

# Compile Device Files
(
    source $TOOLCHAIN_PATH/environment-setup-armv8a-poky-linux
    bear --append --output $CCJ -- make pci_ep KERNEL_DIR=$TOOLCHAIN_ROOT 2> >(grep -v "bear/libexec.so" >&2)
    bear --append --output $CCJ -- make integrated_nnc KERNEL_DIR=$TOOLCHAIN_ROOT 2> >(grep -v "bear/libexec.so" >&2)
)

#Compile Host Files
(
    bear --append --output $CCJ -- make pcie
)
