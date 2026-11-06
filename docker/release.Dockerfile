# Release image: Alpine, musl, fully static binary.
FROM alpine:3.22
RUN apk add --no-cache bash bzip2 clang cmake coreutils curl elfutils-dev file gcc linux-headers lld \
        make musl-dev perl pkgconf py3-pytest python3 tar xz zlib-dev zlib-static
# ss, for the listener tests. Its own layer so adding it does not reinstall the toolchain.
RUN apk add --no-cache iproute2-ss
ENV CC=clang
WORKDIR /work
