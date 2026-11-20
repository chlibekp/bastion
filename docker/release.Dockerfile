# Release image: Alpine, musl, fully static binary.
FROM alpine:3.22
RUN apk add --no-cache bash bzip2 clang cmake coreutils curl elfutils-dev file gcc linux-headers lld \
        make musl-dev perl pkgconf py3-pytest python3 tar xz zlib-dev zlib-static
# ss for the listener tests, setpriv for the entrypoint-shaped log tests. Their own layer, so
# adding them does not reinstall the toolchain.
RUN apk add --no-cache iproute2-ss setpriv
# Packaging (scripts/package.sh, tests/packaging): nfpm builds the .deb and .rpm; dpkg and rpm
# read them back in the tests. Pinned to Alpine 3.22's signed builds (nfpm is not in Debian).
RUN apk add --no-cache nfpm=2.42.1-r5 dpkg=1.22.15-r0 rpm=4.19.1.1-r2
ENV CC=clang
WORKDIR /work
