#!/usr/bin/bash
# See LICENSE file for copyright and license details.
# Shared build steps of the linux-bore, linux-bore-v2 and -v3 packages.

kmake() {
    env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u MAKEFLAGS \
        -u PKG_CONFIG_SYSROOT_DIR -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_PATH \
        make ARCH=x86_64 "$@"
}

kernel_tree() {
    printf '%s/linux-%s\n' "$srcdir" "$pkgver"
}

kernel_check_config() {
    local option want value failed=0
    local required=(
        BLK_DEV_INITRD:y RD_ZSTD:y DEVTMPFS:y TMPFS:y PROC_FS:y SYSFS:y
        EFI:y EFI_STUB:y BINFMT_ELF:y BINFMT_SCRIPT:y UNIX98_PTYS:y
        MODULES:y MODULE_COMPRESS_ZSTD:y
        SCHED_BORE:y HZ_1000:y PREEMPT_DYNAMIC:y
        SQUASHFS:ym SQUASHFS_ZSTD:y OVERLAY_FS:ym ISO9660_FS:ym BLK_DEV_LOOP:ym
        BLK_DEV_SD:ym BLK_DEV_SR:ym SATA_AHCI:ym BLK_DEV_NVME:ym
        USB_STORAGE:ym USB_UAS:ym USB_XHCI_HCD:ym USB_XHCI_PCI:ym
        EXT4_FS:ym XFS_FS:ym VFAT_FS:ym
        DRM_SIMPLEDRM:y
    )

    for option in "${required[@]}"; do
        want=${option#*:}
        option=${option%%:*}
        value=$(sed -n "s/^CONFIG_$option=//p" .config)
        if [[ -z "$value" || "$want" != *"$value"* ]]; then
            printf 'kernel config: CONFIG_%s is "%s", needs %s\n' "$option" "${value:-unset}" "$want" >&2
            failed=1
        fi
    done

    return "$failed"
}

kernel_build() {
    cd "$(kernel_tree)"

    patch -Np1 < "$(ls "$srcdir"/*bore*.patch)"

    kmake x86_64_defconfig
    scripts/kconfig/merge_config.sh -m .config "$srcdir"/kernel/jade/*.config
    scripts/config --set-str LOCALVERSION "$localversion" \
        --disable LOCALVERSION_AUTO
    kmake olddefconfig
    "$srcdir/kernel/jade/verify.sh" .config "$srcdir"/kernel/jade/*.config
    kernel_check_config

    export KBUILD_BUILD_USER=jadeos KBUILD_BUILD_HOST=jadeos
    KBUILD_BUILD_TIMESTAMP=$(LC_ALL=C date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}")
    export KBUILD_BUILD_TIMESTAMP

    local opt=${kernel_opt_level:-2}
    kmake -j"$GEMSTONE_JOBS" \
        KCFLAGS="-march=$cpu_level -mtune=generic -O$opt" \
        KRUSTFLAGS="-Ctarget-cpu=$cpu_level -Copt-level=$opt" \
        all
    kmake -s kernelrelease > version
}

kernel_package() {
    cd "$(kernel_tree)"
    local kver
    kver=$(<version)

    kmake INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 DEPMOD=/doesnt/exist modules_install
    install -Dm644 "$(kmake -s image_name)" "$pkgdir/usr/lib/modules/$kver/vmlinuz"
    printf '%s\n' "$pkgname" > "$pkgdir/usr/lib/modules/$kver/pkgbase"
    rm -f "$pkgdir/usr/lib/modules/$kver/build" "$pkgdir/usr/lib/modules/$kver/source"
}
