ALL_TESTS="\
    test_bpfc_standalone \
    test_bpfc_linked \
    test_bpfc_filters \
    "

test_bpfc="tests/test_bpfc"

test_bpfc_standalone() {
    $test_bpfc test_standalone
}

test_bpfc_linked() {
    $test_bpfc test_linked
}

test_bpfc_filters() {
    $test_bpfc test_filters
}
