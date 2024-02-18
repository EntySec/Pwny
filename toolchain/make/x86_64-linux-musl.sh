PREFIX=/etc/cross/x86_64/bin/x86_64-linux-musl

cat << EOF
CC=$PREFIX-gcc \
AR=$PREFIX-ar \
CXX=$PREFIX-g++ \
LD=$PREFIX-ld \
OBJDUMP=$PREFIX-objdump \
STRIP=$PREFIX-strip
EOF