ALL_TESTS="test_link_so test_link_a"

test_link_so()
{
        cat >$TMPDIR/libxdptest.c <<EOF
#include <xdp/libxdp.h>
int main(int argc, char **argv) {
    (void) argc; (void) argv;
    (void) xdp_program__open_file("filename", "section_name", NULL);
    return 0;
}
EOF
        check_run $CC -o $TMPDIR/libxdptest $TMPDIR/libxdptest.c $CFLAGS $CPPFLAGS -lxdp $LDLIBS 2>&1
}

test_link_a()
{
        cat >$TMPDIR/libxdptest.c <<EOF
#include <xdp/libxdp.h>
int main(int argc, char **argv) {
    (void) argc; (void) argv;
    (void) xdp_program__open_file("filename", "section_name", NULL);
    return 0;
}
EOF
        check_run $CC -o $TMPDIR/libxdptest $TMPDIR/libxdptest.c $CFLAGS $CPPFLAGS -l:libxdp.a $LDLIBS 2>&1
}
