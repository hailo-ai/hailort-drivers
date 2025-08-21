#!/bin/sh

module="hailo1x_pci"

#unload driver
sudo rmmod $module || exit 1

echo driver is unloaded
