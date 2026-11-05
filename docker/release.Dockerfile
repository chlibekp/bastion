# Release image: Alpine, musl, fully static binary.
FROM alpine:3.22
RUN apk add --no-cache bash bzip2 clang cmake coreutils curl elfutils-dev file gcc linux-headers lld \
        make musl-dev perl pkgconf python3 tar xz zlib-dev zlib-static
ENV CC=clang
WORKDIR /work
