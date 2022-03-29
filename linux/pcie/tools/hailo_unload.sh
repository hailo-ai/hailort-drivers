#!/bin/sh

module="hailo_pci"

#unload driver
sudo rmmod $module || exit 1

echo driver is unloaded
