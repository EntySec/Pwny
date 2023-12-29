cat << EOF
CFLAGS="-arch arm64 -isysroot $SDK -Wno-implicit-function-declaration" \
LDFLAGS="-arch arm64 -isysroot $SDK"
EOF
