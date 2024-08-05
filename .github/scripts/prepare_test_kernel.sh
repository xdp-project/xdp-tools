#!/bin/bash

set -e

IFS=- read KERNEL_UPSTREAM_VERSION KERNEL_PATCH_VERSION <<< $KERNEL_VERSION
KERNEL_VERSION_COMPLETE="$KERNEL_VERSION".x86_64
PACKAGES_URL=https://kojipkgs.fedoraproject.org/packages/kernel/
PACKAGES_URL+="$KERNEL_UPSTREAM_VERSION"/"$KERNEL_PATCH_VERSION"/x86_64

for package in core modules modules-core modules-extra devel; do
    # modules-core package only exists for newer kernel versions, so continue if
    # download fails
    wget -nv "$PACKAGES_URL"/kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm || continue
    rpm2cpio kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm | cpio -di
done
find lib -name "*.xz" -exec xz -d {} \;

mv lib/modules/"$KERNEL_VERSION_COMPLETE" kernel
mkdir -p kernel/arch/x86/boot
cp kernel/vmlinuz kernel/arch/x86/boot/bzImage
cp kernel/config kernel/.config
rsync -a usr/src/kernels/"$KERNEL_VERSION_COMPLETE"/ kernel/

find kernel
