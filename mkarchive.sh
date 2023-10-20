#!/bin/bash

WORKDIR=$(dirname "${BASH_SOURCE[0]}")
VERSION="${1:-$(make -f $WORKDIR/version.mk)}"
OUTFILE="$WORKDIR/xdp-tools-$VERSION.tar.gz"
PREFIX=xdp-tools-$VERSION
TMPDIR=$(mktemp -d)

set -o errexit
set -o nounset

trap 'status=$?; rm -rf $TMPDIR; exit $status' EXIT HUP INT QUIT TERM

[ -d .git ] || exit 1
if git status -s | grep -Eq '^ ?[AM]'; then
    echo "Please commit changes first" >&2
    exit 1
fi

git archive -o "$TMPDIR/xdp-tools.tar.gz" --prefix "${PREFIX}/" HEAD
( cd lib/libbpf && git archive -o "$TMPDIR/libbpf.tar.gz" --prefix "${PREFIX}/lib/libbpf/" HEAD)
tar -C "$TMPDIR" -xzf "$TMPDIR/xdp-tools.tar.gz"
tar -C "$TMPDIR" -xzf "$TMPDIR/libbpf.tar.gz"
tar -C "$TMPDIR" -czf "$OUTFILE" "$PREFIX"


echo "Created $OUTFILE"
