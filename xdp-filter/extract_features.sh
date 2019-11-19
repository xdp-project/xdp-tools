#!/bin/sh

cat<<EOF
#ifndef PROG_FEATURES_H
#define PROG_FEATURES_H
struct prog_feature {
	char *prog_name;
	__u32 features;
};

static struct prog_feature prog_features[] = {
EOF

for f in $*; do
    featstring=$(readelf -x features $f 2>/dev/null)
    [ "$?" -ne "0" ] && continue

    found=0
    for w in $featstring; do
        if [ "$w" = "0x00000000" ]; then
            found=1
        else
            if [ "$found" -eq "1" ]; then
                feats=$w
                break
            fi
        fi
    done

    echo "	{\"$f\", 0x$feats},"
done

cat<<EOF
	{}
};
#endif
EOF
