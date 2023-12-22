SDK=/Users/felix/Desktop/iOS-SDKs/iPhoneOS16.1.sdk
COMPAT=/Users/felix/Desktop/Pwny/make/compat

cat << EOF
CFLAGS="-arch arm64 -isysroot $SDK -Wno-implicit-function-declaration -I$COMPAT"
EOF