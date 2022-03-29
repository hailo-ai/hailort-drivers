This project contains the source code of the Hailo PCIe driver for Linux.

## Build the driver.
Run the command `make all`. The driver will be compiled with the current running
kernel, in order to cross compile, the user needs to set the KERNEL_DIR environment variable.
 
## Install/Uninstall the driver
 Run the command `sudo make install` or `sudo make uninstall`

## Load the driver
Run the command `sudo modprobe hailo_pci` or `sudo modprobe -r hailo_pci`

## Set driver parameters
There are two options:
- Copy the `hailo_pci.conf` file to `/etc/modprobe.d` and edit the desired parameters.
- Pass the desired parameter in modprobe, for example:
  `sudo modprobe hailo_pci no_power_mode=Y`
