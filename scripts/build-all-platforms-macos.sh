#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
TEMPLATES_DIR="$ROOT_DIR/pwny/templates"

LINUX_TARGETS=(
    "aarch64-linux-musl"
    "armv5l-linux-musleabi"
    "i486-linux-musl"
    "x86_64-linux-musl"
    "powerpc-linux-muslsf"
    "powerpc64le-linux-musl"
    "mips-linux-muslsf"
    "mipsel-linux-muslsf"
    "mips64-linux-musl"
    "s390x-linux-musl"
)

MACOS_TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
)

IOS_TARGET="aarch64-iphone-darwin"
USER_MACOS_SDK=""
USER_IOS_SDK=""
SKIP_LINUX=0
SKIP_MACOS=0
SKIP_IOS=0
SKIP_TARGETS=()
ACTIVE_LINUX_TARGETS=()
ACTIVE_MACOS_TARGETS=()
BUILD_IOS_TARGET=1

log()
{
    printf '[*] %s\n' "$1"
}

fail()
{
    printf '[!] %s\n' "$1" >&2
    exit 1
}

require_cmd()
{
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

usage()
{
    cat <<EOF
Usage: $(basename "$0") [--macos-sdk <path>] [--ios-sdk <path>]

Options:
  --macos-sdk <path>  Override macOS SDK path (default: xcrun --sdk macosx --show-sdk-path)
  --ios-sdk <path>    Override iOS SDK path (default: xcrun --sdk iphoneos --show-sdk-path)
  --skip-linux        Skip all Linux targets
  --skip-macos        Skip all macOS targets
  --skip-ios          Skip iOS target
  --skip-target <t>   Skip specific target triplet (repeatable)
  -h, --help          Show this help message
EOF
}

is_in_array()
{
    local needle="$1"
    shift

    local value
    for value in "$@"; do
        if [ "$value" = "$needle" ]; then
            return 0
        fi
    done

    return 1
}

is_target_skipped()
{
    local target="$1"
    is_in_array "$target" "${SKIP_TARGETS[@]+${SKIP_TARGETS[@]}}"
}

compute_active_targets()
{
    local target
    local known_targets=("${LINUX_TARGETS[@]}" "${MACOS_TARGETS[@]}" "$IOS_TARGET")

    for target in "${SKIP_TARGETS[@]+${SKIP_TARGETS[@]}}"; do
        [ -n "$target" ] || continue
        is_in_array "$target" "${known_targets[@]}" || fail "Unknown skip target: $target"
    done

    ACTIVE_LINUX_TARGETS=()
    ACTIVE_MACOS_TARGETS=()
    BUILD_IOS_TARGET=1

    if [ "$SKIP_LINUX" -eq 0 ]; then
        for target in "${LINUX_TARGETS[@]}"; do
            if ! is_target_skipped "$target"; then
                ACTIVE_LINUX_TARGETS+=("$target")
            fi
        done
    fi

    if [ "$SKIP_MACOS" -eq 0 ]; then
        for target in "${MACOS_TARGETS[@]}"; do
            if ! is_target_skipped "$target"; then
                ACTIVE_MACOS_TARGETS+=("$target")
            fi
        done
    fi

    if [ "$SKIP_IOS" -ne 0 ] || is_target_skipped "$IOS_TARGET"; then
        BUILD_IOS_TARGET=0
    fi

    if [ "${#ACTIVE_LINUX_TARGETS[@]}" -eq 0 ] && [ "${#ACTIVE_MACOS_TARGETS[@]}" -eq 0 ] && [ "$BUILD_IOS_TARGET" -eq 0 ]; then
        fail "All targets are skipped. Nothing to build."
    fi
}

parse_args()
{
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --macos-sdk)
                [ "$#" -ge 2 ] || fail "Missing value for --macos-sdk"
                USER_MACOS_SDK="$2"
                shift 2
                ;;
            --ios-sdk)
                [ "$#" -ge 2 ] || fail "Missing value for --ios-sdk"
                USER_IOS_SDK="$2"
                shift 2
                ;;
            --skip-linux)
                SKIP_LINUX=1
                shift
                ;;
            --skip-macos)
                SKIP_MACOS=1
                shift
                ;;
            --skip-ios)
                SKIP_IOS=1
                shift
                ;;
            --skip-target)
                [ "$#" -ge 2 ] || fail "Missing value for --skip-target"
                SKIP_TARGETS+=("$2")
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Unknown argument: $1"
                ;;
        esac
    done
}

DOCKER_BASE_IMAGE="${DOCKER_BASE_IMAGE:-ubuntu:24.04}"
DOCKER_IMAGE="${DOCKER_IMAGE:-pwny-build-env:ubuntu24.04}"
CROSS_CACHE_VOLUME="${CROSS_CACHE_VOLUME:-pwny-cross-cache}"

build_deps()
{
    local target="$1"
    local sdk="${2:-}"

    log "Building dependencies for $target"
    if [ -n "$sdk" ]; then
        make -C "$ROOT_DIR" TARGET="$target" SDK="$sdk"
    else
        make -C "$ROOT_DIR" TARGET="$target"
    fi
}

ensure_docker_image()
{
    if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
        return
    fi

    log "Building Docker image: $DOCKER_IMAGE"
    docker build -t "$DOCKER_IMAGE" --build-arg BASE_IMAGE="$DOCKER_BASE_IMAGE" - <<'EOF'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    binutils \
    ca-certificates \
    cmake \
    curl \
    file \
    git \
    libtool \
    make \
    perl \
    pkg-config \
    python3 \
    wget \
    xz-utils && \
    rm -rf /var/lib/apt/lists/*

RUN printf '%s\n' '#!/usr/bin/env bash' 'objcopy -O binary "$1" "$2"' > /usr/local/bin/elf2bin && \
    chmod +x /usr/local/bin/elf2bin
EOF
}

build_linux_targets_in_docker()
{
    local targets=("$@")
    local linux_targets_str
    linux_targets_str="${targets[*]}"

    ensure_docker_image
    docker volume create "$CROSS_CACHE_VOLUME" >/dev/null

    log "Building Linux targets in Docker image: $DOCKER_IMAGE"
    docker run --rm \
        -v "$ROOT_DIR:/workspace" \
        -v "$CROSS_CACHE_VOLUME:/etc/cross" \
        -w /workspace \
        -e LINUX_TARGETS="$linux_targets_str" \
        -e HOST_UID="$(id -u)" \
        -e HOST_GID="$(id -g)" \
        "$DOCKER_IMAGE" \
        bash -lc '
            set -euo pipefail

            ensure_cross_target() {
                local target="$1"
                local archive="${target}-cross"
                local tmp="/tmp/${archive}.tgz"

                [ -d "/etc/cross/$target" ] && return 0

                echo "[*] [docker] Downloading cross-compiler for $target"
                wget -q -O "$tmp" "https://musl.cc/${archive}.tgz"
                tar -xzf "$tmp" -C /etc/cross
                rm -f "$tmp"

                if [ -d "/etc/cross/${archive}" ] && [ ! -d "/etc/cross/$target" ]; then
                    mv "/etc/cross/${archive}" "/etc/cross/$target"
                fi
            }

            deps_ready() {
                local target="$1"
                local libdir="deps/build/${target}/lib"

                [ -f "${libdir}/libcurl.a" ] && \
                [ -f "${libdir}/libev.a" ] && \
                [ -f "${libdir}/libeio.a" ] && \
                [ -f "${libdir}/libsigar.a" ] && \
                [ -f "${libdir}/libmbedtls.a" ] && \
                [ -f "${libdir}/libmbedx509.a" ] && \
                [ -f "${libdir}/libmbedcrypto.a" ] && \
                [ -f "${libdir}/libz.a" ] && \
                [ -f "${libdir}/libpawn.a" ]
            }

            mkdir -p /etc/cross

            if [ -z "$(ls -A /etc/cross 2>/dev/null || true)" ]; then
                echo "[*] [docker] Installing cross-compilers via scripts/cross.sh"
                bash scripts/cross.sh
            fi

            for target in $LINUX_TARGETS; do
                ensure_cross_target "$target"
            done

            failed_targets=()

            for target in $LINUX_TARGETS; do
                exe_template="pwny/templates/${target}.exe"
                bin_template="pwny/templates/${target}.bin"

                if [ -f "$exe_template" ] && [ -f "$bin_template" ]; then
                    echo "[*] [docker] Skipping $target (templates already exist)"
                    continue
                fi

                if ! deps_ready "$target"; then
                    echo "[*] [docker] Building dependencies for $target"
                    if ! make TARGET="$target"; then
                        echo "[!] [docker] Dependency build failed for $target"
                        failed_targets+=("$target")
                        continue
                    fi
                else
                    echo "[*] [docker] Skipping dependencies for $target (already built)"
                fi

                if [ -f "$exe_template" ] && [ ! -f "$bin_template" ]; then
                    echo "[*] [docker] Creating missing .bin template for $target"
                    if elf2bin "$exe_template" "$bin_template"; then
                        chmod +x "$bin_template"
                        continue
                    fi
                fi

                rm -rf build
                echo "[*] [docker] Building Pwny for $target"
                if ! cmake -DCMAKE_TOOLCHAIN_FILE="toolchain/cmake/${target}.cmake" \
                           -DMAIN=ON \
                           -DSOURCE="src/main/main.c" \
                           -B build; then
                    echo "[!] [docker] CMake configure failed for $target"
                    failed_targets+=("$target")
                    continue
                fi

                if ! cmake --build build --parallel "$(nproc)"; then
                    echo "[!] [docker] Build failed for $target"
                    failed_targets+=("$target")
                    continue
                fi

                cp build/main "$exe_template"
                chmod +x "$exe_template"

                if elf2bin build/main "$bin_template"; then
                    chmod +x "$bin_template"
                else
                    echo "[!] [docker] Failed to create .bin for $target"
                    failed_targets+=("$target")
                fi
            done

            chown -R "$HOST_UID:$HOST_GID" pwny/templates deps/build || true
            rm -rf build

            if [ ${#failed_targets[@]} -ne 0 ]; then
                echo "[!] [docker] Linux targets failed: ${failed_targets[*]}"
                exit 2
            fi
        '
}

configure_and_build_main()
{
    local target="$1"
    local source_file="$2"
    local bundle="$3"
    local sdk="$4"

    rm -rf "$BUILD_DIR"

    local cmake_args=(
        -DCMAKE_TOOLCHAIN_FILE="$ROOT_DIR/toolchain/cmake/${target}.cmake"
        -DMAIN=ON
        -DSOURCE="$source_file"
        -B "$BUILD_DIR"
    )

    if [ "$bundle" = "ON" ]; then
        cmake_args+=( -DBUNDLE=ON )
    fi

    if [ -n "$sdk" ]; then
        cmake_args+=( -DCMAKE_OSX_SYSROOT="$sdk" )
    fi

    log "Configuring main for $target"
    cmake "$ROOT_DIR" "${cmake_args[@]}"

    log "Building main for $target"
    cmake --build "$BUILD_DIR" --parallel "$(sysctl -n hw.ncpu)"

}

resolve_main_output()
{
    local target="$1"

    if [ -f "$BUILD_DIR/main" ]; then
        printf '%s\n' "$BUILD_DIR/main"
        return
    fi

    if [ "$target" = "$IOS_TARGET" ] && [ -f "$BUILD_DIR/main.app/main" ]; then
        printf '%s\n' "$BUILD_DIR/main.app/main"
        return
    fi

    fail "Missing build output for $target (checked: $BUILD_DIR/main, $BUILD_DIR/main.app/main)"
}

install_exe_template()
{
    local target="$1"
    local input_binary="$2"
    local output_template="$TEMPLATES_DIR/${target}.exe"

    mkdir -p "$TEMPLATES_DIR"
    cp "$input_binary" "$output_template"
    chmod +x "$output_template"

    log "Installed template: $output_template"
}

build_macos_target()
{
    local target="$1"
    local sdk="$2"
    local main_output

    build_deps "$target" "$sdk"
    configure_and_build_main "$target" "src/main/main.c" "OFF" "$sdk"
    main_output="$(resolve_main_output "$target")"
    install_exe_template "$target" "$main_output"
}

build_ios_target()
{
    local target="$1"
    local sdk="$2"
    local main_output
    local sign_plist="$ROOT_DIR/deps/sign.plist"

    require_cmd ct_bypass
    require_cmd ldid

    build_deps "$target" "$sdk"
    configure_and_build_main "$target" "src/main/mussel.m" "ON" "$sdk"
    main_output="$(resolve_main_output "$target")"

    local mussel_binary="$BUILD_DIR/mussel"
    cp "$main_output" "$mussel_binary"

    [ -f "$sign_plist" ] || fail "Missing entitlements file: $sign_plist"
    log "Fake-signing iOS mussel binary with ldid"
    ldid -S"$sign_plist" "$mussel_binary"

    log "Processing iOS mussel binary with ct_bypass"
    ct_bypass -i "$mussel_binary" -o "$mussel_binary" -r

    install_exe_template "$target" "$mussel_binary"
}

main()
{
    parse_args "$@"
    compute_active_targets

    require_cmd cmake
    require_cmd make

    local macos_sdk=""
    local ios_sdk=""
    local linux_stage_failed=0
    local need_macos_sdk=0
    local need_ios_sdk=0

    if [ "${#ACTIVE_LINUX_TARGETS[@]}" -gt 0 ]; then
        require_cmd docker
    fi

    if [ "${#ACTIVE_MACOS_TARGETS[@]}" -gt 0 ]; then
        need_macos_sdk=1
    fi

    if [ "$BUILD_IOS_TARGET" -ne 0 ]; then
        need_ios_sdk=1
    fi

    if { [ "$need_macos_sdk" -ne 0 ] && [ -z "$USER_MACOS_SDK" ]; } || { [ "$need_ios_sdk" -ne 0 ] && [ -z "$USER_IOS_SDK" ]; }; then
        require_cmd xcrun
    fi

    if [ "$need_macos_sdk" -ne 0 ]; then
        if [ -n "$USER_MACOS_SDK" ]; then
            macos_sdk="$USER_MACOS_SDK"
        else
            macos_sdk="$(xcrun --sdk macosx --show-sdk-path)"
        fi
    fi

    if [ "$need_ios_sdk" -ne 0 ]; then
        if [ -n "$USER_IOS_SDK" ]; then
            ios_sdk="$USER_IOS_SDK"
        else
            ios_sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
        fi
    fi

    if [ "$need_macos_sdk" -ne 0 ]; then
        [ -n "$macos_sdk" ] || fail "Failed to resolve macOS SDK path"
        [ -d "$macos_sdk" ] || fail "macOS SDK path does not exist: $macos_sdk"
        log "Using macOS SDK: $macos_sdk"
    fi

    if [ "$need_ios_sdk" -ne 0 ]; then
        [ -n "$ios_sdk" ] || fail "Failed to resolve iOS SDK path"
        [ -d "$ios_sdk" ] || fail "iOS SDK path does not exist: $ios_sdk"
        log "Using iOS SDK: $ios_sdk"
    fi

    if [ "${#ACTIVE_LINUX_TARGETS[@]}" -gt 0 ]; then
        if ! build_linux_targets_in_docker "${ACTIVE_LINUX_TARGETS[@]}"; then
            linux_stage_failed=1
            log "Linux stage completed with failures. Continuing with remaining targets."
        fi
    else
        log "Skipping Linux stage"
    fi

    if [ "${#ACTIVE_MACOS_TARGETS[@]}" -gt 0 ]; then
        for target in "${ACTIVE_MACOS_TARGETS[@]}"; do
            build_macos_target "$target" "$macos_sdk"
        done
    else
        log "Skipping macOS stage"
    fi

    if [ "$BUILD_IOS_TARGET" -ne 0 ]; then
        build_ios_target "$IOS_TARGET" "$ios_sdk"
    else
        log "Skipping iOS stage"
    fi

    rm -rf "$BUILD_DIR"

    if [ "$linux_stage_failed" -ne 0 ]; then
        fail "Completed with Linux target failures. Re-run script to resume failed targets only."
    fi

    log "All targets completed successfully"
}

main "$@"
