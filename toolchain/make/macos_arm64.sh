COMPAT=../../../../make/compat

cat << EOF
CFLAGS="-arch arm64 -isysroot $SDK -Wno-implicit-function-declaration -I$COMPAT"
EOF