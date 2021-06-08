#!/bin/bash

set -e

if [[ "$KERNEL_VERSION" == "LATEST" ]]; then
    git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git kernel
    cd kernel
    cp "$GITHUB_WORKSPACE"/.github/scripts/.config .config
    make -j $(nproc) olddefconfig all
else
    KERNEL_VERSION_COMPLETE="$KERNEL_VERSION"-"$KERNEL_PATCH_VERSION".x86_64
    PACKAGES_URL=https://kojipkgs.fedoraproject.org/packages/kernel/
    PACKAGES_URL+="$KERNEL_VERSION"/"$KERNEL_PATCH_VERSION"/x86_64

    for package in core modules modules-extra devel; do
        wget -nv "$PACKAGES_URL"/kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm
        rpm2cpio kernel-"$package"-"$KERNEL_VERSION_COMPLETE".rpm | cpio -di
    done
    find lib -name "*.xz" -exec xz -d {} \;

    mv lib/modules/"$KERNEL_VERSION_COMPLETE" kernel
    mkdir -p kernel/arch/x86/boot
    cp kernel/vmlinuz kernel/arch/x86/boot/bzImage
    cp kernel/config kernel/.config
    rsync -a usr/src/kernels/"$KERNEL_VERSION_COMPLETE"/ kernel/
fi