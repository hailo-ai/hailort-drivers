#!/bin/sh
set -eu

DRIVER_NAME="hailo_pci"

if { [ "$#" -ne 1 ] && [ "$#" -ne 3 ]; } || ! printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Usage: $0 DRIVER_VERSION [--kernel KERNEL_RELEASE]" >&2
    exit 2
fi
case "$1" in
    *[!0-9.]*) echo "Invalid driver version" >&2; exit 2 ;;
esac

# A single argument keeps the previous version-scoped, all-kernels interface.
if [ "$#" -eq 3 ]; then
    if [ "$2" != --kernel ] || ! printf '%s\n' "$3" | grep -Eq '^[[:alnum:]][[:alnum:]._+-]*$'; then
        echo "Expected --kernel KERNEL_RELEASE" >&2
        exit 2
    fi
    case "$3" in
        *[![:alnum:]._+-]*) echo "Invalid kernel release" >&2; exit 2 ;;
    esac
fi

if ! command -v dkms >/dev/null 2>&1; then
    echo "dkms is required to remove $DRIVER_NAME/$1" >&2
    exit 1
fi

# Let DKMS uninstall each kernel instance and update its state.  Never
# delete /var/lib/dkms, /lib/modules or /usr/src using unscoped globs.
if [ "$#" -eq 3 ]; then
    dkms remove -m "$DRIVER_NAME" -v "$1" -k "$3"
else
    dkms remove -m "$DRIVER_NAME" -v "$1" --all
fi
