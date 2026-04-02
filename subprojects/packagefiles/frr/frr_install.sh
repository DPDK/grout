#!/bin/sh
set -e

frr_srcdir=${1?frr srcdir}
frr_installdir=${2?frr installdir}

# Create config dir
mkdir -p "$frr_installdir/etc/frr"

mkdir -m 0755 -p "$frr_installdir/var/log/frr"
mkdir -m 0700 -p "$frr_installdir/var/lib/frr"
mkdir -m 0700 -p "$frr_installdir/var/run/frr"

# Copy main config files
cp "$frr_srcdir/tools/etc/frr/frr.conf" "$frr_installdir/etc/frr/"
cp "$frr_srcdir/tools/etc/frr/daemons" "$frr_installdir/etc/frr/"

# Optional: also copy vtysh.conf (used to control integrated config)
if [ -f "$frr_srcdir/tools/etc/frr/vtysh.conf" ]; then
    cp "$frr_srcdir/tools/etc/frr/vtysh.conf" "$frr_installdir/etc/frr/"
fi

# Optional: watchfrr.conf (used by watchfrr daemon if present)
if [ -f "$frr_srcdir/tools/etc/frr/watchfrr.conf" ]; then
    cp "$frr_srcdir/tools/etc/frr/watchfrr.conf" "$frr_installdir/etc/frr/"
fi
