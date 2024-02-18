PREFIX=x86_64-w64-mingw32

cat << EOF
CC=$PREFIX-gcc \
AR=$PREFIX-ar \
CXX=$PREFIX-g++ \
LD=$PREFIX-ld \
OBJDUMP=$PREFIX-objdump \
STRIP=$PREFIX-strip
EOF
