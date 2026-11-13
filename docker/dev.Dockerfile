# Development and test image (glibc: ASan and TSan need it).
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash build-essential bzip2 ca-certificates clang cmake cpio curl file git iproute2 kmod \
        libclang-rt-dev libelf-dev lld llvm make nghttp2-client perl pkg-config python3 python3-pytest \
        qemu-system-arm qemu-system-x86 qemu-utils linux-libc-dev xz-utils zstd zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
# Python test dependencies for the proxy tests (HTTP/2 client mode, gRPC), pinned to exact
# Debian trixie versions.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-grpcio=1.51.1-6 python3-grpc-tools=1.14.1-8+deb13u1 \
        python3-h2=4.2.0-1 python3-hpack=4.0.0-3 \
    && rm -rf /var/lib/apt/lists/*
# Mount point for the stock kernel's modules when this root is shared into the test VM (scripts/vm-run.sh).
RUN mkdir -p /lib/modules
# Debian's curl has no HTTP/3 (checked at build time, informational only).
RUN curl --version | head -n 2
ENV CC=clang
WORKDIR /work
