#!/bin/bash

set -e

IFS=- read KERNEL_UPSTREAM_VERSION KERNEL_PATCH_VERSION <<< $KERNEL_VERSION

KERNEL_VERSION_COMPLETE="$KERNEL_UPSTREAM_VERSION"-"$KERNEL_PATCH_VERSION"."$KERNEL_ARCH"
PACKAGES_URL=https://kojipkgs.fedoraproject.org/packages/kernel/
PACKAGES_URL+="$KERNEL_UPSTREAM_VERSION"/"$KERNEL_PATCH_VERSION"/"$KERNEL_ARCH"

for package in core modules modules-extra devel; do
    wget -nv "$PACKAGES_URL"/kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm
    rpm2cpio kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm | cpio -di
done
find lib -name "*.xz" -exec xz -d {} \;

KERNEL_ARCHDIR=x86
[[ "$KERNEL_ARCH" == "aarch64" ]] && KERNEL_ARCHDIR=arm64
[[ "$KERNEL_ARCH" == "ppc64le" ]] && KERNEL_ARCHDIR=ppc64le
[[ "$KERNEL_ARCH" == "s390x" ]] && KERNEL_ARCHDIR=s390

mv lib/modules/"$KERNEL_VERSION_COMPLETE" kernel
mkdir -p kernel/arch/$KERNEL_ARCHDIR/boot
cp kernel/vmlinuz kernel/arch/$KERNEL_ARCHDIR/boot/bzImage
cp kernel/config kernel/.config
rsync -a usr/src/kernels/"$KERNEL_VERSION_COMPLETE"/ kernel/
