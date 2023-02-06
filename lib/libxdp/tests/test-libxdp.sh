ALL_TESTS="test_link_so test_link_a"

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
