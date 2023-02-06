# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

ALL_TESTS="test_link_so test_link_a test_old_dispatcher test_xdp_frags test_xsk_prog_refcnt_bpffs test_xsk_prog_refcnt_legacy"

TESTS_DIR=$(dirname "${BASH_SOURCE[0]}")

test_link_so()
{
        TMPDIR=$(mktemp --tmpdir -d libxdp-test.XXXXXX)
        cat >$TMPDIR/libxdptest.c <<EOF
#include <xdp/libxdp.h>
int main(int argc, char **argv) {
    (void) argc; (void) argv;
    (void) xdp_program__open_file("filename", "section_name", NULL);
    return 0;
}
EOF
        $CC -o $TMPDIR/libxdptest $TMPDIR/libxdptest.c $CFLAGS $CPPFLAGS -lxdp $LDLIBS 2>&1
        retval=$?
        rm -rf "$TMPDIR"
        return $retval
}

test_link_a()
{
        TMPDIR=$(mktemp --tmpdir -d libxdp-test.XXXXXX)
        cat >$TMPDIR/libxdptest.c <<EOF
#include <xdp/libxdp.h>
int main(int argc, char **argv) {
    (void) argc; (void) argv;
    (void) xdp_program__open_file("filename", "section_name", NULL);
    return 0;
}
EOF
        $CC -o $TMPDIR/libxdptest $TMPDIR/libxdptest.c $CFLAGS $CPPFLAGS -l:libxdp.a $LDLIBS 2>&1
        retval=$?
        rm -rf "$TMPDIR"
        return $retval
}

test_refcnt_once()
{
	# We need multiple queues for this test
	NUM_QUEUES_REQUIRED=3
        ip link add xsk_veth0 numrxqueues $NUM_QUEUES_REQUIRED type veth peer name xsk_veth1
        check_run $TESTS_DIR/test_xsk_refcnt xsk_veth0 2>&1
        ip link delete xsk_veth0
}

check_mount_bpffs()
{
	mount | grep -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/ || echo "Unable to mount /sys/fs/bpf"
	mount | grep -q /sys/fs/bpf
}

check_unmount_bpffs()
{
	mount | grep -q /sys/fs/bpf && umount /sys/fs/bpf/ || echo "Unable to unmount /sys/fs/bpf"
	! mount | grep -q /sys/fs/bpf
}

test_xsk_prog_refcnt_bpffs()
{
	check_mount_bpffs && test_refcnt_once "$@"
}

test_xsk_prog_refcnt_legacy()
{
	check_unmount_bpffs && test_refcnt_once "$@"
}

test_xdp_frags()
{
        skip_if_missing_libxdp_compat

        check_mount_bpffs || return 1
        ip link add xdp_veth_big0 mtu 5000 type veth peer name xdp_veth_big1 mtu 5000
        ip link add xdp_veth_small0 type veth peer name xdp_veth_small1
        check_run $TESTS_DIR/test_xdp_frags xdp_veth_big0 xdp_veth_small0 2>&1
        ip link delete xdp_veth_big0
        ip link delete xdp_veth_small0
}

test_old_dispatcher()
{
        skip_if_missing_libxdp_compat

        check_mount_bpffs || return 1
        ip link add xdp_veth0 type veth peer name xdp_veth1
        check_run $TESTS_DIR/test_dispatcher_versions xdp_veth0
        ip link delete xdp_veth0
}

cleanup_tests()
{
    ip link del dev xdp_veth_big0 >/dev/null 2>&1
    ip link del dev xdp_veth_small0 >/dev/null 2>&1
    ip link del dev xsk_veth0 >/dev/null 2>&1
}
