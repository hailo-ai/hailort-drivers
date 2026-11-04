#!/bin/sh
# Non-invasive checks: no DKMS registration or system module changes.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PCIE="$REPO/linux/pcie"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/bin"
cat > "$TMP/bin/dkms" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$DKMS_CALL_LOG"
MOCK
chmod +x "$TMP/bin/dkms"

export DKMS_CALL_LOG="$TMP/dkms-calls"
PATH="$TMP/bin:$PATH" sh "$PCIE/dkms_uninstall.sh" 4.24.0
EXPECTED='remove -m hailo_pci -v 4.24.0 --all'
ACTUAL=$(cat "$DKMS_CALL_LOG")
[ "$ACTUAL" = "$EXPECTED" ] || {
    echo "FAIL: wrong DKMS removal: $ACTUAL" >&2; exit 1;
}

: > "$DKMS_CALL_LOG"
for invalid in '4.24.0;exit' '4.24' '../4.24.0' ''; do
    if PATH="$TMP/bin:$PATH" sh "$PCIE/dkms_uninstall.sh" "$invalid" >/dev/null 2>&1; then
        echo "FAIL: accepted invalid driver version: $invalid" >&2
        exit 1
    fi
done
[ ! -s "$DKMS_CALL_LOG" ] || {
    echo 'FAIL: DKMS was called with an invalid version' >&2; exit 1;
}

# Make dry-runs expand recipes but must not run them.
INSTALL=$(cd "$PCIE" && make -n install_dkms)
UNINSTALL=$(cd "$PCIE" && make -n uninstall)

printf '%s\n' "$INSTALL" | grep -F 'dkms add -m hailo_pci -v 4.24.0' >/dev/null
printf '%s\n' "$INSTALL" | grep -F 'dkms install -m hailo_pci -v 4.24.0' >/dev/null
if printf '%s\n' "$INSTALL" | grep -Eq '^dkms install .*--force|^sh dkms_uninstall.sh'; then
    echo 'FAIL: installer still uses --force or uninstalls' >&2; exit 1
fi
printf '%s\n' "$UNINSTALL" | grep -F 'sh dkms_uninstall.sh "4.24.0"' >/dev/null
if printf '%s\n' "$UNINSTALL" | grep -Eq 'rm -rf .*(/var/lib/dkms|/lib/modules|/usr/src)'; then
    echo 'FAIL: uninstall contains destructive unscoped removal' >&2; exit 1
fi

echo 'PASS: scoped DKMS removal, input validation, and non-destructive Makefile recipes'
