PREFIX=/etc/cross/aarch64/bin/aarch64-linux-musl

cat << EOF
CC=$PREFIX-gcc \
AR=$PREFIX-ar \
CXX=$PREFIX-g++ \
LD=$PREFIX-ld \
OBJDUMP=$PREFIX-objdump \
STRIP=$PREFIX-strip
EOF