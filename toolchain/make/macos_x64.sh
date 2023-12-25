COMPAT=../../../../make/compat

cat << EOF
CFLAGS="-arch x86_64 -isysroot $SDK -Wno-implicit-function-declaration -I$COMPAT"
EOF