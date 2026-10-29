This project contains the source code of the Hailo PCIe driver for Linux.

## Build the driver.
Run the command `make all`. The driver will be compiled with the current running
kernel, in order to cross compile, the user needs to set the KERNEL_DIR environment variable.
 
## Install/Uninstall the driver

`sudo make install` installs a standalone module using Kbuild.
`sudo make install_dkms` registers, builds and installs the current driver
version through DKMS. It never implicitly uninstalls an existing version and
does not use `--force`. An existing registration or source tree is refused.
DKMS build and install select `kernelver` (the running kernel by default).

Removal is explicitly separated by installation type:

| Target | Removal scope |
| --- | --- |
| `sudo make uninstall` | Alias for `uninstall_dkms`: this driver version, selected `kernelver` only. |
| `sudo make uninstall_dkms kernelver=KERNEL_RELEASE` | This DKMS driver version for that kernel; DKMS owns file removal, original-module restoration and depmod. |
| `sudo make uninstall_all_dkms` | This DKMS driver version for all kernels; never other driver versions. |
| `sudo make uninstall_standalone` | Fails closed without deleting files: legacy standalone installations have no reliable installer ownership records. |

The old `uninstall` target could remove both installation types; it no longer
falls back to standalone cleanup. Automatic removal after a non-DKMS
`make install` is unsupported, as explained below. An absent DKMS registration is reported by
DKMS as an error, rather than being treated as permission to delete a module.
The restored `uninstall_all_dkms` target now means all kernels of the selected
version, not all installed driver versions. Direct `sh dkms_uninstall.sh VERSION`
retains its version-scoped all-kernels interface; add `--kernel KERNEL_RELEASE`
to select one kernel.

Matching module name, version, kernel metadata, pathname or even byte content
does not establish which installer owns that file. Absence of a DKMS entry is
not positive evidence of standalone ownership either. No automatic standalone
cleanup is provided until installation records reliable provenance. The refusal
also covers same-version originals restored by DKMS, malformed/unreadable files,
compressed modules and symbolic links. No metadata parsing or filesystem deletion
is attempted by the standalone target.

After a non-DKMS installation, retain the module and inspect its installer or
package-manager provenance; `uninstall_standalone` does not offer a force flag or
turn version matching into authorization to delete it. Even an already absent
standalone installation returns the unsupported-operation error. Normal DKMS
removal does not unload the running module. Serialize lifecycle actions; these
recipes do not provide a lock against concurrent package/DKMS changes.

DKMS installation is not an atomic transaction: a failed copy/add/build/install
may leave source or registration state which must be inspected before retry.
No automatic broad cleanup or removal of a previous installation is used as
rollback. The separate SDK/standalone source-layout issue is unchanged. Real
installation, restoration, signing and rollback tests require a disposable VM.

### Hardware-free regression tests

Inside the development container, run:

```sh
python3 -B -m unittest discover -s tests/dkms_lifecycle -v
```

These tests execute the Make targets and shell helpers against private fixtures
below `.workbench/tmp/`. DKMS, deletion, depmod and the root prerequisite are
mocked; the processes remain non-root. No system module or DKMS state is used.
To additionally verify preservation of real compressed module artifacts, set
`HAILO_REAL_TEST_MODULE` to an absolute path to a previously GCC-built `.ko`
below `.workbench/tmp/`. The test copies/compresses that artifact and verifies
that the standalone refusal leaves every copy unchanged, including matching
name/version/kernel metadata; installation/removal commands remain fixture-only.

## Load the driver
Run the command `sudo modprobe hailo_pci` or `sudo modprobe -r hailo_pci`

## Set driver parameters
There are two options:
- Copy the `hailo_pci.conf` file to `/etc/modprobe.d` and edit the desired parameters.
- Pass the desired parameter in modprobe, for example:
  `sudo modprobe hailo_pci no_power_mode=Y`
