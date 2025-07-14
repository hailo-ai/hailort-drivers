#!/bin/bash

COMPONENTS="pcie pci_ep integrated_nnc"

BASE_DIR=`pwd`
CCJ=compile_commands.json

rm -f $CCJ && touch $CCJ && echo "{}" > $CCJ

for component in $COMPONENTS; do
    cd ./linux/$component
    bear --append --output $BASE_DIR/$CCJ -- make clean all
    cd $BASE_DIR
done;
